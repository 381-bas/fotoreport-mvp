# app_pg.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import io
import os
import hashlib
import secrets
from datetime import datetime, date
from typing import Optional, Tuple

import pandas as pd
import streamlit as st
from PIL import Image, ImageOps

import psycopg
from psycopg.rows import dict_row

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader


APP_TITLE = "FotoReport · MVP (Supabase Postgres)"


def get_db_url() -> str:
    # 1) local: env var
    if os.getenv("DATABASE_URL"):
        return os.getenv("DATABASE_URL")
    # 2) Streamlit Cloud: secrets
    try:
        return st.secrets["DATABASE_URL"]
    except Exception:
        return ""


# =========================
# DB helpers (Postgres)
# =========================
def db_connect():
    db_url = get_db_url()
    if not db_url:
        raise RuntimeError("Falta DATABASE_URL (env o st.secrets).")

    if "pg_con" not in st.session_state or st.session_state.pg_con.closed:
        # prepare_threshold=None: CLAVE para Supabase pooler (transaction)
        st.session_state.pg_con = psycopg.connect(
            db_url,
            row_factory=dict_row,
            prepare_threshold=None,
        )
    return st.session_state.pg_con


def db_exec(sql: str, params: tuple = ()) -> None:
    con = db_connect()
    with con.cursor() as cur:
        cur.execute(sql, params)
    con.commit()


def db_query(sql: str, params: tuple = ()):
    con = db_connect()
    with con.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# =========================
# Password hashing (PBKDF2)
# =========================
def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)


def create_user(usuario: str, nombre_completo: str, rol: str, password: str, email: str = "") -> None:
    salt = secrets.token_bytes(16)
    ph = hash_password(password, salt)
    db_exec(
        """
        INSERT INTO usuarios(usuario, nombre_completo, email, rol, pw_salt, pw_hash, activo, creado_en)
        VALUES(%s,%s,%s,%s,%s,%s,1,%s)
        """,
        (usuario.strip().lower(), nombre_completo.strip(), email.strip(), rol, salt, ph, now_ts()),
    )


def verify_login(usuario: str, password: str) -> Optional[dict]:
    rows = db_query(
        """
        SELECT id, usuario, nombre_completo, rol, pw_salt, pw_hash, activo
        FROM usuarios
        WHERE usuario = %s
        """,
        (usuario.strip().lower(),),
    )
    if not rows:
        return None
    r = rows[0]
    if int(r["activo"]) != 1:
        return None

    test = hash_password(password, r["pw_salt"])
    if secrets.compare_digest(test, r["pw_hash"]):
        return {"id": int(r["id"]), "usuario": r["usuario"], "nombre": r["nombre_completo"], "rol": r["rol"]}
    return None


def admins_exist() -> bool:
    r = db_query("SELECT COUNT(*) AS n FROM usuarios WHERE rol='admin' AND (activo::int=1)")[0]
    return int(r["n"]) > 0


# =========================
# Data helpers
# =========================
def get_clientes():
    return db_query("SELECT id, nombre FROM clientes WHERE (activo::int=1) ORDER BY nombre")


def get_locales():
    return db_query("""
        SELECT l.id, l.nombre_local, l.codigo_local, c.nombre AS cliente, l.direccion, l.ciudad
        FROM locales l
        JOIN clientes c ON c.id = l.cliente_id
        WHERE (l.activo::int=1) AND (c.activo::int=1)
        ORDER BY c.nombre, l.nombre_local
    """)


def get_locales_asignados(usuario_id: int):
    return db_query("""
        SELECT l.id, l.nombre_local, l.codigo_local, c.nombre AS cliente, l.direccion, l.ciudad
        FROM asignaciones a
        JOIN locales l ON l.id = a.local_id
        JOIN clientes c ON c.id = l.cliente_id
        WHERE (a.activo::int=1) AND (l.activo::int=1) AND (c.activo::int=1)
          AND a.usuario_id=%s
        ORDER BY c.nombre, l.nombre_local
    """, (usuario_id,))


# =========================
# Imagen -> bytes
# =========================
def normalize_image_bytes(raw: bytes, target_quality: int = 80) -> Tuple[bytes, str]:
    img = Image.open(io.BytesIO(raw))
    img = ImageOps.exif_transpose(img)
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    out = io.BytesIO()
    img.save(out, format="JPEG", quality=target_quality)
    return out.getvalue(), "image/jpeg"


def insert_reporte(local_id: int, usuario_id: int, fecha_visita: str, notas: str) -> int:
    con = db_connect()
    with con.cursor() as cur:
        cur.execute("""
            INSERT INTO reportes(local_id, usuario_id, fecha_visita, notas, creado_en)
            VALUES(%s,%s,%s,%s,%s)
            RETURNING id
        """, (local_id, usuario_id, fecha_visita, notas.strip(), now_ts()))
        rid = cur.fetchone()["id"]
    con.commit()
    return int(rid)


def insert_foto(reporte_id: int, nombre_archivo: str, mime: str, imagen_bytes: bytes, comentario: str) -> None:
    db_exec("""
        INSERT INTO fotos(reporte_id, nombre_archivo, mime, imagen_bytes, comentario, creado_en)
        VALUES(%s,%s,%s,%s,%s,%s)
    """, (reporte_id, nombre_archivo, mime, imagen_bytes, comentario.strip(), now_ts()))


def _fit(iw: int, ih: int, mw: float, mh: float) -> Tuple[float, float]:
    if iw <= 0 or ih <= 0:
        return mw, mh
    s = min(mw / iw, mh / ih)
    return iw * s, ih * s


def _bytes(v):
    return v.tobytes() if isinstance(v, memoryview) else v


def build_pdf_cliente(cliente_id: int, desde: str, hasta: str) -> bytes:
    cli = db_query("SELECT nombre FROM clientes WHERE id=%s", (cliente_id,))
    cliente = cli[0]["nombre"] if cli else "Cliente"

    reportes = db_query("""
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
        WHERE l.cliente_id = %s
          AND r.fecha_visita BETWEEN %s AND %s
        ORDER BY r.fecha_visita, l.nombre_local, r.id
    """, (cliente_id, desde, hasta))

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    W, H = A4

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
        fotos = db_query("""
            SELECT nombre_archivo, mime, imagen_bytes, comentario
            FROM fotos
            WHERE reporte_id=%s
            ORDER BY id
        """, (rid,))

        c.setFont("Helvetica-Bold", 14)
        title = f"{r['fecha_visita']} · {r['nombre_local']}"
        if r["codigo_local"]:
            title += f" ({r['codigo_local']})"
        c.drawString(40, H - 50, title)

        c.setFont("Helvetica", 10)
        c.drawString(40, H - 68, f"Trabajador: {r['trabajador']} | {r['ciudad'] or ''}")

        y = H - 110
        max_w = W - 80
        max_h = (H - 170) / 2

        for i, f in enumerate(fotos):
            raw = _bytes(f["imagen_bytes"])
            img = Image.open(io.BytesIO(raw))
            img = ImageOps.exif_transpose(img)
            if img.mode not in ("RGB", "L"):
                img = img.convert("RGB")

            tmp = io.BytesIO()
            img.save(tmp, format="JPEG", quality=80)
            tmp.seek(0)
            ir = ImageReader(tmp)

            iw, ih = img.size
            dw, dh = _fit(iw, ih, max_w, max_h)
            c.drawImage(ir, 40, y - dh, width=dw, height=dh, preserveAspectRatio=True, anchor="nw")

            cap = (f["comentario"] or "").strip()
            if cap:
                c.setFont("Helvetica", 9)
                c.drawString(40, y - dh - 12, cap[:140])

            y = y - dh - 30
            if (i % 2) == 1 and i < len(fotos) - 1:
                c.showPage()
                y = H - 50

        c.showPage()

    c.save()
    return buf.getvalue()


# =========================
# UI
# =========================
st.set_page_config(page_title=APP_TITLE, layout="wide")
st.title(APP_TITLE)

if not get_db_url():
    st.error("Falta DATABASE_URL (env o Secrets).")
    st.stop()

if "user" not in st.session_state:
    st.session_state.user = None
if "photo_buffer" not in st.session_state:
    st.session_state.photo_buffer = []


def logout():
    st.session_state.user = None
    st.session_state.photo_buffer = []


if not admins_exist():
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
            create_user(usuario, nombre, "admin", pw1, email=email)
            st.success("Admin creado. Ahora inicia sesión.")
    st.stop()


if not st.session_state.user:
    st.subheader("Login")
    c1, c2 = st.columns(2)
    with c1:
        u = st.text_input("Usuario")
    with c2:
        p = st.text_input("Password", type="password")
    if st.button("Entrar"):
        user = verify_login(u, p)
        if user:
            st.session_state.user = user
            st.rerun()
        else:
            st.error("Credenciales inválidas o usuario inactivo.")
    st.stop()


user = st.session_state.user
st.sidebar.write(f"**Sesión:** {user['nombre']} · `{user['rol']}`")
st.sidebar.button("Salir", on_click=logout)

pages = ["Nuevo reporte", "Mis reportes"]
if user["rol"] == "admin":
    pages = ["Admin", "Nuevo reporte", "Mis reportes", "PDF por cliente"]

page = st.sidebar.radio("Módulo", pages, index=0)


if page == "Admin":
    st.subheader("Admin (gestión base)")
    t1, t2, t3, t4 = st.tabs(["Clientes", "Locales", "Usuarios", "Asignaciones"])

    with t1:
        with st.form("new_cliente"):
            nombre = st.text_input("Nombre cliente")
            ok = st.form_submit_button("Crear")
        if ok:
            db_exec("INSERT INTO clientes(nombre, activo, creado_en) VALUES(%s,1,%s)", (nombre.strip(), now_ts()))
            st.success("Cliente creado.")
        st.dataframe(pd.DataFrame(db_query("SELECT * FROM clientes ORDER BY nombre")), use_container_width=True)

    with t2:
        clientes = get_clientes()
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
                db_exec("""
                    INSERT INTO locales(cliente_id, codigo_local, nombre_local, direccion, ciudad, activo, creado_en)
                    VALUES(%s,%s,%s,%s,%s,1,%s)
                """, (cmap[cliente], codigo.strip(), nombre_local.strip(), direccion.strip(), ciudad.strip(), now_ts()))
                st.success("Local creado.")
        st.dataframe(pd.DataFrame(get_locales()), use_container_width=True)

    with t3:
        with st.form("new_user"):
            usuario = st.text_input("Usuario")
            nombre = st.text_input("Nombre completo")
            email = st.text_input("Email (opcional)")
            rol = st.selectbox("Rol", ["trabajador", "admin"])
            pw1 = st.text_input("Password", type="password")
            pw2 = st.text_input("Repite password", type="password")
            ok = st.form_submit_button("Crear usuario")
        if ok:
            if pw1 != pw2:
                st.error("Passwords no coinciden.")
            else:
                create_user(usuario, nombre, rol, pw1, email=email)
                st.success("Usuario creado.")
        st.dataframe(pd.DataFrame(db_query("""
            SELECT id, usuario, nombre_completo, email, rol, activo, creado_en
            FROM usuarios
            ORDER BY rol, usuario
        """)), use_container_width=True)

    with t4:
        users = db_query("SELECT id, usuario, nombre_completo FROM usuarios WHERE (activo::int=1) ORDER BY usuario")
        stores = get_locales()
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
                db_exec("""
                    INSERT INTO asignaciones(usuario_id, local_id, activo, asignado_en)
                    VALUES(%s,%s,1,%s)
                    ON CONFLICT (usuario_id, local_id) DO NOTHING
                """, (umap[ulabel], smap[slabel], now_ts()))
                st.success("Asignación creada (o ya existía).")

        st.dataframe(pd.DataFrame(db_query("""
            SELECT a.id, u.usuario, u.nombre_completo, c.nombre AS cliente, l.nombre_local, a.activo, a.asignado_en
            FROM asignaciones a
            JOIN usuarios u ON u.id=a.usuario_id
            JOIN locales l ON l.id=a.local_id
            JOIN clientes c ON c.id=l.cliente_id
            ORDER BY u.usuario, c.nombre, l.nombre_local
        """)), use_container_width=True)


elif page == "Nuevo reporte":
    st.subheader("Nuevo reporte")

    locales = get_locales() if user["rol"] == "admin" else get_locales_asignados(user["id"])
    if not locales:
        st.info("No tienes locales asignados (o no hay locales).")
        st.stop()

    lmap = {f"{r['cliente']} · {r['nombre_local']}": int(r["id"]) for r in locales}
    llabel = st.selectbox("Local", options=list(lmap.keys()))
    local_id = lmap[llabel]

    fecha = st.date_input("Fecha visita", value=date.today())
    notas = st.text_area("Notas (opcional)")

    up = st.file_uploader("Subir fotos (cámara/galería)", type=["jpg", "jpeg", "png"], accept_multiple_files=True)
    comentario = st.text_input("Comentario (opcional)")

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
        st.success(f"Agregadas: {added}") if added else st.warning("No agregaste fotos.")

    if st.session_state.photo_buffer:
        st.write(f"Fotos en buffer: **{len(st.session_state.photo_buffer)}**")
        cols = st.columns(4)
        for i, ph in enumerate(st.session_state.photo_buffer[:12]):
            img = Image.open(io.BytesIO(ph["bytes"]))
            cols[i % 4].image(img, caption=ph.get("comentario") or ph["nombre_archivo"], use_container_width=True)

        if st.button("Guardar reporte"):
            rid = insert_reporte(local_id, user["id"], fecha.strftime("%Y-%m-%d"), notas)
            for ph in st.session_state.photo_buffer:
                insert_foto(rid, ph["nombre_archivo"], ph["mime"], ph["bytes"], ph.get("comentario", ""))
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
        rows = db_query("""
            SELECT r.id, r.fecha_visita, r.notas,
                   l.nombre_local, c.nombre AS cliente,
                   u.nombre_completo AS trabajador
            FROM reportes r
            JOIN locales l ON l.id=r.local_id
            JOIN clientes c ON c.id=l.cliente_id
            JOIN usuarios u ON u.id=r.usuario_id
            WHERE r.fecha_visita BETWEEN %s AND %s
            ORDER BY r.fecha_visita DESC, r.id DESC
        """, (d1.strftime("%Y-%m-%d"), d2.strftime("%Y-%m-%d")))
    else:
        rows = db_query("""
            SELECT r.id, r.fecha_visita, r.notas,
                   l.nombre_local, c.nombre AS cliente
            FROM reportes r
            JOIN locales l ON l.id=r.local_id
            JOIN clientes c ON c.id=l.cliente_id
            WHERE r.usuario_id=%s AND r.fecha_visita BETWEEN %s AND %s
            ORDER BY r.fecha_visita DESC, r.id DESC
        """, (user["id"], d1.strftime("%Y-%m-%d"), d2.strftime("%Y-%m-%d")))

    if not rows:
        st.info("Sin reportes.")
        st.stop()

    dfv = pd.DataFrame(rows)
    st.dataframe(dfv, use_container_width=True)

    rid = st.number_input("Ver fotos del reporte (id)", min_value=0, value=int(dfv.iloc[0]["id"]))
    fotos = db_query("SELECT id, nombre_archivo, comentario, imagen_bytes FROM fotos WHERE reporte_id=%s ORDER BY id", (int(rid),))
    if fotos:
        cols = st.columns(4)
        for i, f in enumerate(fotos):
            raw = _bytes(f["imagen_bytes"])
            img = Image.open(io.BytesIO(raw))
            cols[i % 4].image(img, caption=f["comentario"] or f["nombre_archivo"], use_container_width=True)
    else:
        st.warning("No hay fotos para ese reporte.")


elif page == "PDF por cliente":
    st.subheader("PDF por cliente")
    clientes = get_clientes()
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

    if "pdf_bytes" not in st.session_state:
        st.session_state.pdf_bytes = None
        st.session_state.pdf_name = None

    if st.button("Generar PDF"):
        pdf = build_pdf_cliente(cid, d1.strftime("%Y-%m-%d"), d2.strftime("%Y-%m-%d"))
        st.session_state.pdf_bytes = pdf
        st.session_state.pdf_name = f"Reporte_{cname}_{d1.strftime('%Y%m%d')}_{d2.strftime('%Y%m%d')}.pdf"
        st.success("PDF listo para descargar.")

    if st.session_state.pdf_bytes:
        st.download_button(
            "Descargar PDF",
            data=st.session_state.pdf_bytes,
            file_name=st.session_state.pdf_name,
            mime="application/pdf",
            key="dl_pdf"
        )
