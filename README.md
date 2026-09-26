# Protocolo-de-Implementacion_CR3

### Información General

- *Nombre del Proyecto:* Sistema de Monitoreo de Integridad Academica
- *Descripción:* El proyecto consiste en un sistema que crea una red para un grupo de estudiantes de un salón, lo que permitirá al docente monitorear los dispositivos de los estudiantes para evitar hacer trampas, como buscar en otras páginas o abrir otros sitios, para ello el sistema hará una inspección pasiva monitoreando y clasificando el tráfico, guardando la información de los dispositivos en una BD para saber que dispositivos están autorizados y cuales no.
- *Integrantes del equipo desarrollador:*
  - Bravo Linares, Favio Gabrielle
  - Huanqui Luque, Pierol Yaren
  - Huayapa Alata, Gabriel Jaret
  - Quispe Cusi, Jean Luis
  - Zegarra Mamani, Renzo Leonel

- Tecnologías Utilizadas:
  - Lenguaje de backend: Python
  - Framework web: Flask
  - Captura y análisis de paquetes: Scapy
  - Identificación de fabricante por MAC: mac-vendor-lookup
  - Motor de plantillas / frontend: HTML, CSS, Bootstrap, Jinja2
  - Base de datos: MySQL
  - ORM: SQLAlchemy
  - Cifrado de datos sensibles: cryptography (Fernet)

- Requisitos:
  - MySQL Server
  - Python
  - Librerías Python
    - Flask
    - Scapy
    - mac-vendor-lookup
    - SQLAlquemy
    - cryptography
    - PyJWT
- Procedimiento básico de instalación y ejecución:
  - Clonar o descargar el proyecto y abrir una terminal en la carpeta raíz.
  - Crear y activar el entorno virtual en Windows con: "python -m venv venv" y "venv\Scripts\activate"
  - Instalar las depedencias con: "pip install flask scapy mac-vendor-lookup flask-sqlalchemy cryptography pyjwt"
  - Configurar la bases de datos
  - Ejecutar la aplicación con: "python main.py"
  - Abrir el navegador e ingresar a: "http://localhost:5000 (o la IP/puerto configurado)"
  




