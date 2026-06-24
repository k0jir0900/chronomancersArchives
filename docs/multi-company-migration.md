# Multi-Company Migration Plan

Propuesta de migracion de Chronomancers Archives a multi-empresa (multi-tenant)
con rol superAdmin y restriccion de visibilidad por company. Documento de
trabajo para continuar la implementacion mas adelante.

Estado: propuesta aprobada, pendiente de implementar.

---

## 1. Contexto / estado actual

- No existe el concepto de "company" como entidad. `company` es solo una columna
  de texto libre `VARCHAR(255)` en `archives` (`docker/mysql/001_init.sql:15`).
  No hay tabla de empresas ni relacion con usuarios.
- El registro de CDU tiene la empresa hardcodeada: `company = 'CMPC'` en
  `register` (`src/app.py:1230`). El formulario `register.html` no pide company.
- El filtrado por company ya esta disperso por el codigo, siempre por el string:
  `home`, `history` (`:857`, `:899`), `mitre_coverage` (`:1401`, `:1416`),
  `search`, `reports` / `build_report_data` (`:247`). Hoy ninguno restringe nada: cualquier usuario logueado ve todas las
  empresas.
- Roles actuales: `admin`, `user`, `service`, `third_party`
  (`users.html:111-114`). `admin_required` chequea estricto `role == 'admin'`
  (`:1844`).
- Usuario base `admin` se crea en `init_db` con rol `admin` (`:635-639`).
- Patron de migracion existente: `init_db` aplica `ALTER TABLE ... try/except`
  idempotentes (`:540-588`). Es el mecanismo a reutilizar para las tablas nuevas
  sin romper el restore de backups.

---

## 2. Decisiones confirmadas

1. **Gestion de companies y asignacion a usuarios: superAdmin y admin.** Ambos
   roles pueden crear/editar/eliminar empresas y asignarlas a usuarios.
2. **Vinculo de datos: migrar a `company_id`.** Se anade `company_id` FK a
   `archives` con backfill, en vez de scoping por nombre.
3. **superAdmin ve todo.** Sin restriccion de company; el selector le lista todas
   las empresas con opcion `All`.

---

## 3. Modelo de datos

Tablas nuevas creadas en `init_db` (idempotente, `CREATE TABLE IF NOT EXISTS`):

```
companies
  id INT PK AUTO_INCREMENT
  name VARCHAR(255) NOT NULL UNIQUE
  is_active TINYINT NOT NULL DEFAULT 1
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

user_companies
  user_id    INT NOT NULL
  company_id INT NOT NULL
  PRIMARY KEY (user_id, company_id)
  FK user_id    -> users(id)      ON DELETE CASCADE
  FK company_id -> companies(id)  ON DELETE CASCADE
```

Cambios en `archives` (via ALTER idempotente en `init_db`):

```
ADD COLUMN company_id INT NULL  (FK -> companies(id))
ADD INDEX  idx_company_id
```

Se mantiene la columna `company` (texto) poblada en paralelo para no romper el
restore de backups viejos ni la visualizacion. `company_id` pasa a ser la clave
de scoping y de joins. Migrar a "solo id" se puede dejar para una segunda fase.

### Backfill (una vez, idempotente)

```sql
INSERT IGNORE INTO companies (name)
  SELECT DISTINCT company FROM archives
  WHERE company IS NOT NULL AND company <> '';

UPDATE archives a
  JOIN companies c ON a.company = c.name
  SET a.company_id = c.id
  WHERE a.company_id IS NULL;
```

---

## 4. Roles

- Nuevo rol `superadmin`. Usuario base `admin` migra a `superadmin`:
  `UPDATE users SET role='superadmin' WHERE username='admin'` (solo si sigue
  siendo `admin`), y cambiar la creacion del usuario base a `superadmin`.
- Jerarquia: `superadmin` puede todo lo de `admin`. `admin_required` debe
  aceptar tambien `superadmin`.
- Gestion de companies y asignacion usan `@admin_required` (ambos roles pasan,
  segun decision 2.1).
- Anadir `superadmin` al `<select>` de roles en `users.html`.

---

## 5. Capa de scoping global (nucleo del cambio)

Un unico helper reutilizable, fuente de verdad de "que empresas puede ver el
request actual":

```python
def allowed_company_ids():
    # superadmin -> None  (sin restriccion, ve todo)
    # resto      -> lista de company_id desde user_companies ([] = no ve nada)

def company_filter(alias=''):
    # devuelve (sql_fragment, params), p.ej. ("a.company_id IN (%s,%s)", [...])
    # respeta ademas la company activa del selector (seccion 8)
```

Aplicar en CADA ruta que lee `archives`:

- `home`
- `history`
- `diff_rules`
- `mitre_coverage`
- `search_cdu`
- `reports` / `build_report_data`

Tambien en los `SELECT DISTINCT company` que llenan filtros: pasan a
`SELECT id, name FROM companies` filtrado por las companies permitidas, para que
el usuario ni vea nombres de empresas ajenas.

Regla por defecto (fallo seguro): usuario sin companies asignadas no ve nada.
superAdmin es la unica excepcion (ve todo).

---

## 6. Gestion de Companies (CRUD)

- Rutas nuevas con `@admin_required`:
  - `GET  /companies`            (lista)
  - `POST /companies/add`
  - `POST /companies/edit/<id>`
  - `POST /companies/delete/<id>`
- Eliminar = `is_active = 0` (soft delete) si la empresa tiene `archives`
  asociados, para no perder trazabilidad del historico.
- Plantilla nueva `companies.html` (mismo estilo que `users.html`).
- Entrada de menu en `base.html` bajo "User Management" (visible para admin y
  superadmin).

---

## 7. Asignacion de companies a usuarios

- Multi-select de companies por usuario en `users.html`.
- Ruta nueva `POST /users/<id>/companies` que reescribe `user_companies`.
- `add_user` admite asignacion inicial de companies.

---

## 8. Selector global de company (dropdown junto al nombre)

- En `base.html` topbar, a la izquierda del nombre de usuario: dropdown con
  opciones `All` + empresas, visible si es superadmin o si el usuario tiene mas
  de 1 company asignada.
- Seleccion guardada en `session['active_company']` via ruta ligera
  `POST /set-company` (con CSRF). Default `all`.
- `company_filter()` respeta el selector: si hay company activa valida dentro de
  las permitidas, filtra a esa; si es `all`, filtra a todas las permitidas.
- Validacion en servidor: nunca se permite seleccionar una company fuera del set
  asignado.

---

## 9. Registro de CDU

`register` deja de hardcodear `'CMPC'`. El formulario pide la empresa, limitada a
las companies del usuario (o usa la company activa del selector si no es `all`).
Validar en servidor que la company enviada este dentro de las permitidas antes
del `INSERT`, y setear `company_id` (+ `company` texto por compatibilidad).

---

## 10. API REST publica de exportacion (ELIMINADA)

Bajo `/api/` hay dos grupos. Distincion importante:

### Endpoints internos AJAX - SE QUEDAN
Llamados por el frontend (`fetch` en plantillas), sostienen los formularios:

- `/api/mitre/techniques`, `/api/mitre/subtechniques/<id>` (register, history)
- `/api/rule/latest`, `/api/rule/mitre`, `/api/rule/tags` (register)
- `/api/tags`, `/api/tags/categories` (register, history)

### API publica de exportacion - ELIMINADA (commit aislado)
- `/api/v1/cdu` (`require_api_key`) - unico endpoint de datos publico
- `/api/docs` + `/api/openapi.json` (`api_docs.html`)
- Subsistema de API keys: tabla `api_keys`, `generate_api_key`,
  `admin_regenerate_api_key`, `admin_delete_api_key`, `require_api_key`, y la
  migracion plaintext->hash en `init_db`
- UI asociada: seccion de API key en `profile.html`, columnas/acciones de key en
  `users.html`, enlaces "Docs" en `base.html:72` y `profile.html:114`

Uso interno: cero. Ningun `fetch` del frontend llama a `/api/v1/cdu`; solo
aparece en `api_docs.html` como ejemplo de `curl`. La unica incognita es externa
(otro equipo / pipeline / SIEM consumiendo con su key), que no se ve en el codigo.

Notas si se elimina:
- `_log_api_audit` SE QUEDA: lo reutiliza el login (`login_success` /
  `login_failed`), igual que la pagina `/audit` y la tabla `api_audit_log`. Solo
  desaparecen las acciones tipo `api_call` / `key_*`.
- Hacerlo en un commit aislado, antes de empezar el multi-company.
- Si se elimina, desaparece el punto de enforcement de scoping en
  `api_export_cdu` y todo el riesgo de fuga por key (simplifica el trabajo).

**Eliminada.** Ya no existe `/api/v1/cdu` ni el subsistema de API keys. `_log_api_audit`, la pagina `/audit` y la tabla `api_audit_log` se conservan (auditoria de login).

---

## 11. Seguridad / auditoria

- Disparar `/security-review` antes del commit (toca sesion, autorizacion,
  input, SQL) segun CLAUDE.md.
- Registrar en `api_audit_log` las acciones nuevas (`company_created`,
  `company_assigned`, etc.).
- Verificar que ninguna ruta de lectura quede sin `company_filter`: es el punto
  de fallo tipico de multi-tenant.
- `service` / `third_party` tambien deben quedar scopeados por company.

---

## 12. Orden de implementacion

0. [HECHO] API publica de exportacion eliminada en commit aislado (seccion 10).
1. Migracion de esquema + backfill + rol superadmin (`init_db`).
2. Helpers `allowed_company_ids` / `company_filter` + jerarquia en decoradores.
3. Aplicar scoping en las rutas de lectura.
4. Companies CRUD + plantilla + menu.
5. Asignacion en users + selector global en `base.html`.
6. `register` con company.
7. `/code-review` -> `/security-review` -> `/verify`
   (`docker compose up -d --build`, health + logs) -> commit.

---

## 13. Archivos a tocar

- `src/app.py` (grueso del cambio)
- `docker/mysql/001_init.sql`
- `src/templates/base.html` (menu + selector)
- `src/templates/users.html` (rol superadmin + asignacion de companies)
- `src/templates/register.html` (selector de company)
- `src/templates/companies.html` (nuevo)
- Revisar filtros de company en `mitre_coverage.html`, `history.html`,
  `reports.html`, `search.html` (ocultar para usuarios de 1 sola empresa)

---

## 14. Items abiertos

- [x] API publica de exportacion eliminada (commit aislado).
- [ ] Definir UI de asignacion de companies en `users.html` (multi-select vs
      lista de checkboxes).
- [ ] Decidir si los filtros de company existentes (history/reports/mitre) se
      ocultan o se mantienen para usuarios de 1 empresa.
