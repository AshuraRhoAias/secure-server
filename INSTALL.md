# Instalación de secure-server (Linux y Windows)

El proyecto incluye un **instalador multiplataforma** que, al ejecutarse, **pregunta
en qué sistema quieres instalar (Linux o Windows)** e **instala todo lo necesario
mostrando una barra de progreso**.

## Requisito previo

- **Node.js ≥ 18** (incluye `npm`). Descárgalo de <https://nodejs.org> si no lo tienes.

## Cómo instalar

### Opción A — multiplataforma (recomendada)

```bash
node install.js
```

El instalador mostrará un menú para elegir **1) Linux** o **2) Windows** y, a
continuación, ejecutará los pasos con una barra de progreso.

### Opción B — lanzador por sistema

- **Linux / macOS:**
  ```bash
  ./install.sh
  ```
- **Windows (PowerShell):**
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\install.ps1
  ```

## Qué hace el instalador

1. **Comprueba requisitos** (Node ≥ 18 y `npm`).
2. **Instala las dependencias** del proyecto (`npm ci` si hay `package-lock.json`, si no `npm install`).
3. **Prepara `.env`** a partir de `.env.example` si aún no existe (en Linux lo deja con permisos `600`).
4. **Ajusta permisos** (sólo Linux).
5. **(Opcional)** instala el **toolset de seguridad de `PruebasLinux`** (nmap, sslscan,
   nikto, whatweb, bandit, …). En Linux vía `apt`/`pip`; en Windows te indica los
   comandos `winget`/`choco`. Te pregunta antes; se omite con `--no-tools`.
6. **Verificación final**.

## Opciones

| Opción | Efecto |
|--------|--------|
| `--os linux` / `--os windows` | No pregunta el sistema. |
| `--yes` / `-y` | Acepta los pasos opcionales (toolset de seguridad). |
| `--no-tools` | Omite el toolset de `PruebasLinux`. |
| `--help` | Ayuda. |

> En entornos sin terminal interactiva (CI), el instalador detecta el SO y **no** instala
> paquetes del sistema salvo que pases `--yes`.

## Después de instalar

1. Revisa y completa `.env` (credenciales y semillas reales).
2. Crea la base de datos e importa el esquema:
   ```bash
   mysql -u <usuario> -p <base_de_datos> < database/schema.sql
   ```
3. Arranca el servidor:
   ```bash
   npm start
   ```
4. Ejecuta las pruebas de seguridad (laboratorio):
   ```bash
   cd PruebasLinux && ./pruebas.sh
   ```
   En Windows, usa **WSL** o **Git Bash** para el menú de `PruebasLinux` (está escrito en Bash).

Más detalle del entorno de pruebas en [`PruebasLinux/ReadmeLogMejoras.md`](PruebasLinux/ReadmeLogMejoras.md)
y la auditoría en [`ReadmeLogsMejoras.md`](ReadmeLogsMejoras.md).
