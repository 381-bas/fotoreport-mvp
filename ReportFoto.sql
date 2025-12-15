

-- DB: fotoreport
CREATE TABLE IF NOT EXISTS usuarios (
  id              BIGSERIAL PRIMARY KEY,
  usuario         TEXT NOT NULL UNIQUE,
  nombre_completo TEXT NOT NULL,
  email           TEXT,
  rol             TEXT NOT NULL CHECK (rol IN ('admin','trabajador')),
  pw_salt         BYTEA NOT NULL,
  pw_hash         BYTEA NOT NULL,
  activo          BOOLEAN NOT NULL DEFAULT TRUE,
  creado_en       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS clientes (
  id        BIGSERIAL PRIMARY KEY,
  nombre    TEXT NOT NULL UNIQUE,
  activo    BOOLEAN NOT NULL DEFAULT TRUE,
  creado_en TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS locales (
  id           BIGSERIAL PRIMARY KEY,
  cliente_id   BIGINT NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
  codigo_local TEXT,
  nombre_local TEXT NOT NULL,
  direccion    TEXT,
  ciudad       TEXT,
  activo       BOOLEAN NOT NULL DEFAULT TRUE,
  creado_en    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_locales_cliente ON locales(cliente_id);

CREATE TABLE IF NOT EXISTS asignaciones (
  id          BIGSERIAL PRIMARY KEY,
  usuario_id  BIGINT NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  local_id    BIGINT NOT NULL REFERENCES locales(id) ON DELETE CASCADE,
  activo      BOOLEAN NOT NULL DEFAULT TRUE,
  asignado_en TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (usuario_id, local_id)
);

CREATE INDEX IF NOT EXISTS idx_asignaciones_usuario ON asignaciones(usuario_id);
CREATE INDEX IF NOT EXISTS idx_asignaciones_local   ON asignaciones(local_id);

CREATE TABLE IF NOT EXISTS reportes (
  id           BIGSERIAL PRIMARY KEY,
  local_id     BIGINT NOT NULL REFERENCES locales(id) ON DELETE CASCADE,
  usuario_id   BIGINT NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  fecha_visita DATE NOT NULL,
  notas        TEXT,
  creado_en    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_reportes_local_fecha   ON reportes(local_id, fecha_visita);
CREATE INDEX IF NOT EXISTS idx_reportes_usuario_fecha ON reportes(usuario_id, fecha_visita);

CREATE TABLE IF NOT EXISTS fotos (
  id            BIGSERIAL PRIMARY KEY,
  reporte_id    BIGINT NOT NULL REFERENCES reportes(id) ON DELETE CASCADE,
  nombre_archivo TEXT,
  mime          TEXT NOT NULL,
  imagen_bytes  BYTEA NOT NULL,
  comentario    TEXT,
  creado_en     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_fotos_reporte ON fotos(reporte_id);
