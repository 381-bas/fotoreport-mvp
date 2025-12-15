# app.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import io
import sqlite3
import hashlib
import secrets
from datetime import datetime, date
from typing import Optional, List, Dict, Any, Tuple

import pandas as pd
import streamlit as st
from PIL import Image, ImageOps
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader


APP_TITLE = "FotoReport · MVP local (SQLite)"
DB_FILE = "small.db"   # <-- tu DB ya creada


# =========================
# DB helpers
# =========================
def db_connect() -> sqlite3.Connection:
    con = sqlite3.connect(DB_FILE, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON;")
    con.execute("PRAGMA journal_mode = WAL;")
    con.execute("PRAGMA synchronous = NORMAL;")
    return con


def db_exec(con: sqlite3.Connection, sql: str, params: tuple = ()) -> None:
    with con:
        con.execute(sql, params)


def db_query(con: sqlite3.Connection, sql: str, params: tuple = ()) -> List[sqlite3.Row]:
    cur = con.execute(sql, params)
    return cur.fetchall()


def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# =========================
# Password hashing (PBKDF2)
# =========================
def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)


def create_user(con: sqlite3.Connection, usuario: str, nombre_completo: str, rol: str, password: str, email: str = "") -> None:
    salt = secrets.token_bytes(16)
    ph = hash_password(password, salt)
    db_exec(
        con,
        """INSERT INTO usuarios(usuario, nombre_completo, email, rol, pw_salt, pw_hash, activo, creado_en)
           VALUES(?,?,?,?,?,?,1,?)""",
        (usuario.strip().lower(), nombre_completo.strip(), email.strip(), rol, salt, ph, now_ts()),
    )


def verify_login(con: sqlite3.Connection, usuario: str, password: str) -> Optional[dict]:
    rows = db_query(con, """
        SELECT id, usuario, nombre_completo, rol, pw_salt, pw_hash, activo
        FROM usuarios
        WHERE usuario = ?
    """, (usuario.strip().lower(),))
    if not rows:
        return None
    r = rows[0]
    if int(r["activo"]) != 1:
        return None
    test = hash_password(password, r["pw_salt"])
    if secrets.compare_digest(test, r["pw_hash"]):
        return {"id": int(r["id"]), "usuario": r["usuario"], "nombre": r["nombre_completo"], "rol": r["rol"]}
    return None


def admins_exist(con: sqlite3.Connection) -> bool:
    r = db_query(con, "SELECT COUNT(*) AS n FROM usuarios WHERE rol='admin'")[0]
    return int(r["n"]) > 0


# =========================
# Data helpers (MVP)
# =========================
def get_clientes(con: sqlite3.Connection) -> List[sqlite3.Row]:
    return db_query(con, "SELECT id, nombre FROM clientes WHERE activo=1 ORDER BY nombre")

def get_locales(con: sqlite3.Connection) -> List[sqlite3.Row]:
    return db_query(con, """
        SELECT l.id, l.nombre_local, l.codigo_local, c.nombre AS cliente, l.direccion, l.ciudad
        FROM locales l
        JOIN clientes c ON c.id = l.cliente_id
        WHERE l.activo=1 AND c.activo=1
        ORDER BY c.nombre, l.nombre_local
    """)

def get_locales_asignados(con: sqlite3.Connection, usuario_id: int) -> List[sqlite3.Row]:
    return db_query(con, """
        SELECT l.id, l.nombre_local, l.codigo_local, c.nombre AS cliente, l.direccion, l.ciudad
        FROM asignaciones a
        JOIN locales l ON l.id = a.local_id
        JOIN clientes c ON c.id = l.cliente_id
        WHERE a.activo=1 AND l.activo=1 AND c.activo=1
          AND a.usuario_id=?
        ORDER BY c.nombre, l.nombre_local
    """, (usuario_id,))


# =========================
# Imagen -> bytes (reduce errores / tamaño)
# =========================
def normalize_image_bytes(raw: bytes, target_quality: int = 80) -> Tuple[bytes, str]:
    """
    Convierte a JPEG (RGB) para que PDF sea estable y la DB no explote.
    Retorna (bytes_jpeg, mime).
    """
    img = Image.open(io.BytesIO(raw))
    img = ImageOps.exif_transpose(img)
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    out = io.BytesIO()
    img.save(out, format="JPEG", quality=target_quality)
    return out.getvalue(), "image/jpeg"


def insert_reporte(con: sqlite3.Connection, local_id: int, usuario_id: int, fecha_visita: str, notas: str) -> int:
    with con:
        cur = con.execute("""
            INSERT INTO reportes(local_id, usuario_id, fecha_visita, notas, creado_en)
            VALUES(?,?,?,?,?)
        """, (local_id, usuario_id, fecha_visita, notas.strip(), now_ts()))
        return int(cur.lastrowid)


def insert_foto(con: sqlite3.Connection, reporte_id: int, nombre_archivo: str, mime: str, imagen_bytes: bytes, comentario: str) -> None:
    db_exec(con, """
        INSERT INTO fotos(reporte_id, nombre_archivo, mime, imagen_bytes, comentario, creado_en)
        VALUES(?,?,?,?,?,?)
    """, (reporte_id, nombre_archivo, mime, imagen_bytes, comentario.strip(), now_ts()))


# =========================
# PDF (por cliente y rango)
# =========================
def _fit(iw: int, ih: int, mw: float, mh: float) -> Tuple[float, float]:
    if iw <= 0 or ih <= 0:
        return mw, mh
    s = min(mw / iw, mh / ih)
    return iw * s, ih * s


def build_pdf_cliente(con: sqlite3.Connection, cliente_id: int, desde: str, hasta: str) -> bytes:
    cli = db_query(con, "SELECT nombre FROM clientes WHERE id=?", (cliente_id,))
    cliente = cli[0]["nombre"] if cli else "Cliente"

    reportes = db_query(con, """
        SELECT
          r.id AS reporte_id,
          r.fecha_visita,
          r.notas,
          l.nombre_local,
          l.codigo_local,
          l.direccion,
          l.ciudad,
          u.nombre_completo AS trabajador
        FROM reportes r
        JOIN locales l ON l.id = r.local_id
        JOIN usuarios u ON u.id = r.usuario_id
        WHERE l.cliente_id = ?
          AND r.fecha_visita BETWEEN ? AND ?
        ORDER BY r.fecha_visita, l.nombre_local, r.id
    """, (cliente_id, desde, hasta))

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    W, H = A4

    # Portada
    c.setFont("Helvetica-Bold", 18)
    c.drawString(40, H - 60, f"Reporte Fotográfico · {cliente}")
    c.setFont("Helvetica", 11)
    c.drawString(40, H - 85, f"Rango: {desde} a {hasta}")
    c.drawString(40, H - 105, f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    c.showPage()

    if not reportes:
        c.setFont("Helvetica", 12)
        c.drawString(40, H - 60, "Sin reportes en el rango.")
        c.save()
        return buf.getvalue()

    for r in reportes:
        rid = int(r["reporte_id"])
        fotos = db_query(con, """
            SELECT nombre_archivo, mime, imagen_bytes, comentario
            FROM fotos
            WHERE reporte_id=?
            ORDER BY id
        """, (rid,))

        c.setFont("Helvetica-Bold", 14)
        title = f"{r['fecha_visita']} · {r['nombre_local']}"
        if r["codigo_local"]:
            title += f" ({r['codigo_local']})"
        c.drawString(40, H - 50, title)

        c.setFont("Helvetica", 10)
        c.drawString(40, H - 68, f"Trabajador: {r['trabajador']} | {r['ciudad'] or ''}")

        if (r["direccion"] or "").strip():
            c.drawString(40, H - 84, f"Dirección: {r['direccion']}")

        if (r["notas"] or "").strip():
            c.setFont("Helvetica-Oblique", 10)
            c.drawString(40, H - 102, f"Notas: {str(r['notas'])[:120]}")

        y = H - 130
        max_w = W - 80
        max_h = (H - 170) / 2

        for i, f in enumerate(fotos):
            try:
                img = Image.open(io.BytesIO(f["imagen_bytes"]))
                img = ImageOps.exif_transpose(img)
                if img.mode not in ("RGB", "L"):
                    img = img.convert("RGB")

                tmp = io.BytesIO()
                img.save(tmp, format="JPEG", quality=80)
                tmp.seek(0)
                ir = ImageReader(tmp)

                iw, ih = img.size
                dw, dh = _fit(iw, ih, max_w, max_h)
                x = 40
                y_img = y - dh

                c.drawImage(ir, x, y_img, width=dw, height=dh, preserveAspectRatio=True, anchor="nw")

                cap = (f["comentario"] or "").strip()
                if cap:
                    c.setFont("Helvetica", 9)
                    c.drawString(40, y_img - 12, cap[:140])

                y = y_img - 30

                if (i % 2) == 1 and i < len(fotos) - 1:
                    c.showPage()
                    y = H - 50
            except Exception:
                c.setFont("Helvetica", 10)
                c.drawString(40, y, "[No se pudo renderizar una imagen]")
                y -= 20

        c.showPage()

    c.save()
    return buf.getvalue()


# =========================
# UI
# =========================
st.set_page_config(page_title=APP_TITLE, layout="wide")
st.title(APP_TITLE)

con = db_connect()

if "user" not in st.session_state:
    st.session_state.user = None
if "photo_buffer" not in st.session_state:
    st.session_state.photo_buffer = []


def logout():
    st.session_state.user = None
    st.session_state.photo_buffer = []


# 1) Crear admin inicial (una vez)
if not admins_exist(con):
    st.warning("Primera ejecución: crea el ADMIN global (solo una vez).")
    with st.form("bootstrap_admin"):
        usuario = st.text_input("Usuario admin", value="admin")
        nombre = st.text_input("Nombre completo", value="Administrador")
        email = st.text_input("Email (opcional)", value="")
        pw1 = st.text_input("Password", type="password")
        pw2 = st.text_input("Repite password", type="password")
        ok = st.form_submit_button("Crear admin")
    if ok:
        if not usuario.strip() or not nombre.strip() or not pw1:
            st.error("Faltan campos.")
        elif pw1 != pw2:
            st.error("Passwords no coinciden.")
        else:
            try:
                create_user(con, usuario, nombre, "admin", pw1, email=email)
                st.success("Admin creado. Ahora inicia sesión.")
            except Exception as e:
                st.error(f"No se pudo crear: {e}")
    st.stop()


# 2) Login
if not st.session_state.user:
    st.subheader("Login")
    c1, c2 = st.columns(2)
    with c1:
        u = st.text_input("Usuario")
    with c2:
        p = st.text_input("Password", type="password")
    if st.button("Entrar"):
        user = verify_login(con, u, p)
        if user:
            st.session_state.user = user
            st.success(f"Bienvenido, {user['nombre']} ({user['rol']})")
            st.rerun()
        else:
            st.error("Credenciales inválidas o usuario inactivo.")
    st.stop()


# 3) Router por rol
user = st.session_state.user
st.sidebar.write(f"**Sesión:** {user['nombre']} · `{user['rol']}`")
st.sidebar.button("Salir", on_click=logout)

if user["rol"] == "admin":
    pages = ["Admin", "Nuevo reporte", "Mis reportes", "PDF por cliente"]
else:
    pages = ["Nuevo reporte", "Mis reportes"]

page = st.sidebar.radio("Módulo", pages, index=0)

# =========================
# Módulos
# =========================
if page == "Admin":
    st.subheader("Admin (gestión base)")
    t1, t2, t3, t4 = st.tabs(["Clientes", "Locales", "Usuarios", "Asignaciones"])

    with t1:
        st.markdown("### Crear cliente")
        with st.form("new_cliente"):
            nombre = st.text_input("Nombre cliente")
            ok = st.form_submit_button("Crear")
        if ok:
            try:
                db_exec(con, "INSERT INTO clientes(nombre, activo, creado_en) VALUES(?,?,?)",
                        (nombre.strip(), 1, now_ts()))
                st.success("Cliente creado.")
            except Exception as e:
                st.error(f"Error: {e}")
        st.markdown("### Lista")
        st.dataframe(pd.DataFrame([dict(r) for r in db_query(con, "SELECT * FROM clientes ORDER BY nombre")]),
                     use_container_width=True)

    with t2:
        st.markdown("### Crear local")
        clientes = get_clientes(con)
        if not clientes:
            st.info("Primero crea clientes.")
        else:
            cmap = {r["nombre"]: int(r["id"]) for r in clientes}
            with st.form("new_local"):
                cliente = st.selectbox("Cliente", options=list(cmap.keys()))
                codigo = st.text_input("Código local (opcional)")
                nombre_local = st.text_input("Nombre local")
                direccion = st.text_input("Dirección (opcional)")
                ciudad = st.text_input("Ciudad (opcional)")
                ok = st.form_submit_button("Crear local")
            if ok:
                try:
                    db_exec(con, """
                        INSERT INTO locales(cliente_id, codigo_local, nombre_local, direccion, ciudad, activo, creado_en)
                        VALUES(?,?,?,?,?,?,?)
                    """, (cmap[cliente], codigo.strip(), nombre_local.strip(), direccion.strip(), ciudad.strip(), 1, now_ts()))
                    st.success("Local creado.")
                except Exception as e:
                    st.error(f"Error: {e}")

        st.markdown("### Lista")
        st.dataframe(pd.DataFrame([dict(r) for r in get_locales(con)]), use_container_width=True)

    with t3:
        st.markdown("### Crear usuario")
        with st.form("new_user"):
            usuario = st.text_input("Usuario")
            nombre = st.text_input("Nombre completo")
            email = st.text_input("Email (opcional)")
            rol = st.selectbox("Rol", ["trabajador", "admin"])
            pw1 = st.text_input("Password", type="password")
            pw2 = st.text_input("Repite password", type="password")
            ok = st.form_submit_button("Crear usuario")
        if ok:
            if not usuario.strip() or not nombre.strip() or not pw1:
                st.error("Faltan campos.")
            elif pw1 != pw2:
                st.error("Passwords no coinciden.")
            else:
                try:
                    create_user(con, usuario, nombre, rol, pw1, email=email)
                    st.success("Usuario creado.")
                except Exception as e:
                    st.error(f"Error: {e}")

        st.markdown("### Lista")
        st.dataframe(pd.DataFrame([dict(r) for r in db_query(con, """
            SELECT id, usuario, nombre_completo, email, rol, activo, creado_en
            FROM usuarios
            ORDER BY rol, usuario
        """)]), use_container_width=True)

    with t4:
        st.markdown("### Asignar local a trabajador/admin")
        users = db_query(con, "SELECT id, usuario, nombre_completo FROM usuarios WHERE activo=1 ORDER BY usuario")
        stores = get_locales(con)
        if not users or not stores:
            st.info("Necesitas usuarios y locales.")
        else:
            umap = {f"{u['usuario']} · {u['nombre_completo']}": int(u["id"]) for u in users}
            smap = {f"{s['cliente']} · {s['nombre_local']}": int(s["id"]) for s in stores}
            with st.form("assign"):
                ulabel = st.selectbox("Usuario", options=list(umap.keys()))
                slabel = st.selectbox("Local", options=list(smap.keys()))
                ok = st.form_submit_button("Asignar")
            if ok:
                try:
                    db_exec(con, """
                        INSERT OR IGNORE INTO asignaciones(usuario_id, local_id, activo, asignado_en)
                        VALUES(?,?,1,?)
                    """, (umap[ulabel], smap[slabel], now_ts()))
                    st.success("Asignación creada (o ya existía).")
                except Exception as e:
                    st.error(f"Error: {e}")

        st.markdown("### Lista")
        st.dataframe(pd.DataFrame([dict(r) for r in db_query(con, """
            SELECT a.id, u.usuario, u.nombre_completo, c.nombre AS cliente, l.nombre_local, a.activo, a.asignado_en
            FROM asignaciones a
            JOIN usuarios u ON u.id=a.usuario_id
            JOIN locales l ON l.id=a.local_id
            JOIN clientes c ON c.id=l.cliente_id
            ORDER BY u.usuario, c.nombre, l.nombre_local
        """)]), use_container_width=True)


elif page == "Nuevo reporte":
    st.subheader("Nuevo reporte")

    if user["rol"] == "admin":
        locales = get_locales(con)
    else:
        locales = get_locales_asignados(con, user["id"])

    if not locales:
        st.info("No tienes locales asignados (o no hay locales).")
        st.stop()

    lmap = {f"{r['cliente']} · {r['nombre_local']}": int(r["id"]) for r in locales}
    llabel = st.selectbox("Local", options=list(lmap.keys()))
    local_id = lmap[llabel]

    fecha = st.date_input("Fecha visita", value=date.today())
    notas = st.text_area("Notas (opcional)")

    st.markdown("### Fotos")
    up = st.file_uploader("Subir fotos", type=["jpg", "jpeg", "png"], accept_multiple_files=True)
    cam = st.camera_input("Tomar foto (opcional)")
    comentario = st.text_input("Comentario para las fotos agregadas ahora (opcional)")

    if st.button("Agregar al buffer"):
        added = 0
        if up:
            for f in up:
                jpg_bytes, mime = normalize_image_bytes(f.getvalue(), target_quality=80)
                st.session_state.photo_buffer.append({
                    "nombre_archivo": f.name,
                    "mime": mime,
                    "bytes": jpg_bytes,
                    "comentario": comentario,
                })
                added += 1
        if cam:
            jpg_bytes, mime = normalize_image_bytes(cam.getvalue(), target_quality=80)
            st.session_state.photo_buffer.append({
                "nombre_archivo": "camera.jpg",
                "mime": mime,
                "bytes": jpg_bytes,
                "comentario": comentario,
            })
            added += 1

        if added == 0:
            st.warning("No agregaste fotos.")
        else:
            st.success(f"Agregadas: {added}")

    if st.session_state.photo_buffer:
        st.write(f"Fotos en buffer: **{len(st.session_state.photo_buffer)}**")
        cols = st.columns(4)
        for i, ph in enumerate(st.session_state.photo_buffer[:12]):
            try:
                img = Image.open(io.BytesIO(ph["bytes"]))
                cols[i % 4].image(img, caption=ph.get("comentario") or ph["nombre_archivo"], use_container_width=True)
            except Exception:
                cols[i % 4].write("[preview falló]")

        cA, cB = st.columns([1, 1])
        with cA:
            if st.button("Vaciar buffer"):
                st.session_state.photo_buffer = []
                st.rerun()
        with cB:
            if st.button("Guardar reporte"):
                rid = insert_reporte(
                    con,
                    local_id=local_id,
                    usuario_id=user["id"],
                    fecha_visita=fecha.strftime("%Y-%m-%d"),
                    notas=notas
                )
                for ph in st.session_state.photo_buffer:
                    insert_foto(
                        con,
                        reporte_id=rid,
                        nombre_archivo=ph["nombre_archivo"],
                        mime=ph["mime"],
                        imagen_bytes=ph["bytes"],
                        comentario=ph.get("comentario", "")
                    )
                st.session_state.photo_buffer = []
                st.success(f"Reporte guardado (id={rid}).")
    else:
        st.info("Agrega fotos al buffer y luego guarda el reporte.")


elif page == "Mis reportes":
    st.subheader("Mis reportes")
    c1, c2 = st.columns(2)
    with c1:
        d1 = st.date_input("Desde", value=date.today().replace(day=1))
    with c2:
        d2 = st.date_input("Hasta", value=date.today())

    if user["rol"] == "admin":
        rows = db_query(con, """
            SELECT r.id, r.fecha_visita, r.notas,
                   l.nombre_local, c.nombre AS cliente,
                   u.nombre_completo AS trabajador
            FROM reportes r
            JOIN locales l ON l.id=r.local_id
            JOIN clientes c ON c.id=l.cliente_id
            JOIN usuarios u ON u.id=r.usuario_id
            WHERE r.fecha_visita BETWEEN ? AND ?
            ORDER BY r.fecha_visita DESC, r.id DESC
        """, (d1.strftime("%Y-%m-%d"), d2.strftime("%Y-%m-%d")))
    else:
        rows = db_query(con, """
            SELECT r.id, r.fecha_visita, r.notas,
                   l.nombre_local, c.nombre AS cliente
            FROM reportes r
            JOIN locales l ON l.id=r.local_id
            JOIN clientes c ON c.id=l.cliente_id
            WHERE r.usuario_id=? AND r.fecha_visita BETWEEN ? AND ?
            ORDER BY r.fecha_visita DESC, r.id DESC
        """, (user["id"], d1.strftime("%Y-%m-%d"), d2.strftime("%Y-%m-%d")))

    if not rows:
        st.info("Sin reportes.")
        st.stop()

    dfv = pd.DataFrame([dict(r) for r in rows])
    st.dataframe(dfv, use_container_width=True)

    rid = st.number_input("Ver fotos del reporte (id)", min_value=0, value=int(dfv.iloc[0]["id"]))
    fotos = db_query(con, "SELECT id, nombre_archivo, comentario, imagen_bytes FROM fotos WHERE reporte_id=? ORDER BY id", (int(rid),))
    if fotos:
        cols = st.columns(4)
        for i, f in enumerate(fotos):
            try:
                img = Image.open(io.BytesIO(f["imagen_bytes"]))
                cols[i % 4].image(img, caption=f["comentario"] or f["nombre_archivo"], use_container_width=True)
            except Exception:
                cols[i % 4].write("[imagen inválida]")
    else:
        st.warning("No hay fotos para ese reporte.")


elif page == "PDF por cliente":
    st.subheader("PDF por cliente")
    clientes = get_clientes(con)
    if not clientes:
        st.info("No hay clientes.")
        st.stop()

    cmap = {r["nombre"]: int(r["id"]) for r in clientes}
    cname = st.selectbox("Cliente", options=list(cmap.keys()))
    cid = cmap[cname]

    c1, c2 = st.columns(2)
    with c1:
        d1 = st.date_input("Desde", value=date.today().replace(day=1))
    with c2:
        d2 = st.date_input("Hasta", value=date.today())

    if st.button("Construir PDF"):
        pdf = build_pdf_cliente(con, cid, d1.strftime("%Y-%m-%d"), d2.strftime("%Y-%m-%d"))
        st.download_button(
            "Descargar PDF",
            data=pdf,
            file_name=f"Reporte_{cname}_{d1.strftime('%Y%m%d')}_{d2.strftime('%Y%m%d')}.pdf",
            mime="application/pdf",
        )
