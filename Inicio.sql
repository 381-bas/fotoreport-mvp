PRAGMA foreign_keys = ON;

-- =========================
-- TABLA: usuarios
-- =========================
CREATE TABLE IF NOT EXISTS usuarios (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario         TEXT    NOT NULL UNIQUE,
  nombre_completo TEXT    NOT NULL,
  email           TEXT,
  rol             TEXT    NOT NULL CHECK (rol IN ('admin','trabajador')),
  pw_salt         BLOB    NOT NULL,
  pw_hash         BLOB    NOT NULL,
  activo          INTEGER NOT NULL DEFAULT 1,
  creado_en       TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_usuarios_rol_activo
ON usuarios (rol, activo);


-- =========================
-- TABLA: clientes
-- =========================
CREATE TABLE IF NOT EXISTS clientes (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre    TEXT    NOT NULL UNIQUE,
  activo    INTEGER NOT NULL DEFAULT 1,
  creado_en TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_clientes_activo
ON clientes (activo);


-- =========================
-- TABLA: locales
-- =========================
CREATE TABLE IF NOT EXISTS locales (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  cliente_id  INTEGER NOT NULL,
  codigo_local TEXT,
  nombre_local TEXT    NOT NULL,
  direccion   TEXT,
  ciudad      TEXT,
  activo      INTEGER NOT NULL DEFAULT 1,
  creado_en   TEXT    NOT NULL,
  FOREIGN KEY (cliente_id) REFERENCES clientes(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_locales_cliente
ON locales (cliente_id);

CREATE INDEX IF NOT EXISTS idx_locales_activo
ON locales (activo);


-- =========================
-- TABLA: asignaciones (usuarios <-> locales)
-- =========================
CREATE TABLE IF NOT EXISTS asignaciones (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario_id  INTEGER NOT NULL,
  local_id    INTEGER NOT NULL,
  activo      INTEGER NOT NULL DEFAULT 1,
  asignado_en TEXT    NOT NULL,
  UNIQUE (usuario_id, local_id),
  FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
  FOREIGN KEY (local_id)   REFERENCES locales(id)  ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_asignaciones_usuario
ON asignaciones (usuario_id);

CREATE INDEX IF NOT EXISTS idx_asignaciones_local
ON asignaciones (local_id);


-- =========================
-- TABLA: reportes
-- =========================
CREATE TABLE IF NOT EXISTS reportes (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  local_id    INTEGER NOT NULL,
  usuario_id  INTEGER NOT NULL,
  fecha_visita TEXT   NOT NULL,   -- 'YYYY-MM-DD'
  notas       TEXT,
  creado_en   TEXT    NOT NULL,
  FOREIGN KEY (local_id)   REFERENCES locales(id)  ON DELETE CASCADE,
  FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

-- Para PDF por cliente/rango y para "mis reportes"
CREATE INDEX IF NOT EXISTS idx_reportes_local_fecha
ON reportes (local_id, fecha_visita);

CREATE INDEX IF NOT EXISTS idx_reportes_usuario_fecha
ON reportes (usuario_id, fecha_visita);


-- =========================
-- TABLA: fotos
-- =========================
CREATE TABLE IF NOT EXISTS fotos (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  reporte_id    INTEGER NOT NULL,
  nombre_archivo TEXT,
  mime          TEXT    NOT NULL,  -- image/jpeg, image/png
  imagen_bytes  BLOB    NOT NULL,
  comentario    TEXT,
  creado_en     TEXT    NOT NULL,
  FOREIGN KEY (reporte_id) REFERENCES reportes(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_fotos_reporte
ON fotos (reporte_id);
