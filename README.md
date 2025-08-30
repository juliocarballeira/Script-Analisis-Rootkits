# AnalisisRootkits.sh

Herramienta en **Bash** para el análisis y detección de rootkits en sistemas **Linux**.  
Este script fue desarrollado como parte de un **Trabajo de Fin de Máster en Ciberseguridad**, con el objetivo de identificar procesos, conexiones, archivos y usuarios sospechosos, ofreciendo además mecanismos de cuarentena y restauración.

---

## ✨ Características principales
- **Procesos:** detecta y permite actuar sobre procesos sospechosos o maliciosos.  
- **Conexiones de red:** identifica puertos abiertos y conexiones no autorizadas.  
- **Integridad de binarios:** compara con baseline previa (MD5 y SHA-256) para detectar binarios alterados.  
- **Archivos sospechosos:** analiza rutas críticas del sistema en busca de modificaciones anómalas.  
- **Usuarios:** detecta cuentas privilegiadas, duplicadas o mal configuradas, con acciones de bloqueo y cuarentena.  
- **Cuarentena:** aislamiento de procesos, usuarios o archivos sospechosos.  
- **Interfaz en terminal con colores**, para facilitar la interpretación de resultados.

---

## ⚙️ Requisitos
- Distribución Linux (probado en **Kali Linux Rolling Release**).  
- Ejecución con privilegios de **root**.  
- Dependencias comunes: `bash`, `awk`, `grep`, `netstat/ss`, `dpkg`, `coreutils`.

---

## 🚀 Uso
1. Clonar el repositorio:  
   ```bash
   git clone https://github.com/juliocarballeira/AnalisisRootkits.git
   cd AnalisisRootkits

2. Dar permisos de ejecución:
chmod +x AnalisisRootkits.sh


3. Ejecutar como root:
sudo ./AnalisisRootkits.sh




📂 Estructura

AnalisisRootkits.sh → Script principal.

baseline_md5.txt / baseline_sha256.txt → Baselines de integridad.

quarantine/ → Carpeta donde se aíslan archivos y usuarios sospechosos.

whitelist_*.txt → Listas blancas para reducir falsos positivos.

🛡️ Aviso

⚠️ Este script modifica y elimina procesos, archivos y usuarios sospechosos.
Se recomienda ejecutarlo únicamente en entornos de pruebas o análisis forense.
El autor no se hace responsable del mal uso en sistemas de producción.
