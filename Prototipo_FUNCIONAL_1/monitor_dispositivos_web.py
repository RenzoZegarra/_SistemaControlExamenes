"""
Interfaz web para el monitor de dispositivos en red.

Este archivo es una copia funcional independiente de monitor_dispositivos.py.
El archivo original no se modifica. Ejecuta este archivo y abre
http://127.0.0.1:5000 en el navegador.

Requisitos adicionales:
    pip install flask scapy mac-vendor-lookup

En Windows, ejecuta la terminal como administrador y asegúrate de tener Npcap.
"""

from datetime import datetime

from flask import Flask, render_template

try:
    from scapy.all import ARP, Ether, srp
except ImportError:
    print("Falta instalar scapy. Ejecuta: pip install scapy")
    raise SystemExit(1)

try:
    from mac_vendor_lookup import MacLookup
    mac_lookup = MacLookup()
    VENDOR_LOOKUP_AVAILABLE = True
except ImportError:
    VENDOR_LOOKUP_AVAILABLE = False
    print("Aviso: mac_vendor_lookup no instalado. Se mostrará el fabricante como 'Desconocido'.")


# ============================================================
# CONFIGURACIÓN (misma configuración que el archivo original)
# ============================================================

RED_OBJETIVO = "192.168.1.0/24"
DISPOSITIVOS_AUTORIZADOS = {
    "52:4F:DD:5F:2E:1F",
    "42:54:C7:B2:2B:BC",
}
INTERVALO_ESCANEO_SEGUNDOS = 5


# ============================================================
# FUNCIONES DE DETECCIÓN
# ============================================================

def escanear_red(red: str):
    """Envía peticiones ARP broadcast y recolecta las respuestas activas."""
    arp = ARP(pdst=red)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquete = ether / arp
    respuestas = srp(paquete, timeout=3, verbose=False)[0]

    dispositivos = []
    for _enviado, recibido in respuestas:
        dispositivos.append({
            "ip": recibido.psrc,
            "mac": recibido.hwsrc.upper(),
        })
    return dispositivos


def obtener_fabricante(mac: str) -> str:
    if not VENDOR_LOOKUP_AVAILABLE:
        return "Desconocido"
    try:
        return mac_lookup.lookup(mac)
    except Exception:
        return "Desconocido"


def clasificar_estado(mac: str) -> str:
    return "AUTORIZADO" if mac in DISPOSITIVOS_AUTORIZADOS else "NO AUTORIZADO"


# ============================================================
# INTERFAZ WEB (sin JavaScript)
# ============================================================

app = Flask(__name__)


@app.get("/")
def inicio():
    dispositivos = []
    error = None
    escaneo_realizado = False

    try:
        encontrados = escanear_red(RED_OBJETIVO)
        dispositivos = [
            {
                **dispositivo,
                "fabricante": obtener_fabricante(dispositivo["mac"]),
                "estado": clasificar_estado(dispositivo["mac"]),
            }
            for dispositivo in encontrados
        ]
        escaneo_realizado = True
    except Exception as exc:
        error = str(exc)

    return render_template(
        "index.html",
        dispositivos=dispositivos,
        error=error,
        escaneo_realizado=escaneo_realizado,
        red_objetivo=RED_OBJETIVO,
        fecha_escaneo=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
