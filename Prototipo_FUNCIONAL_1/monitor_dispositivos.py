"""
Módulo de Detección de Dispositivos en Red - AVANCE DE PROYECTO
Sistema de Monitoreo de Integridad Académica

Qué hace este script:
- Escanea periódicamente la red local usando peticiones ARP (via scapy).
- Detecta qué dispositivos están conectados (ej. tu celular al conectarse
  por WiFi a la misma red que tu PC / hotspot).
- Muestra en terminal: IP, MAC, fabricante (si es posible obtenerlo) y si el
  dispositivo está AUTORIZADO o NO AUTORIZADO según una lista blanca simple.

Qué NO hace (a propósito, para mantenerlo simple en esta etapa):
- No crea el hotspot/punto de acceso WiFi (eso se activa desde el sistema
  operativo: "Hotspot móvil" en Windows, "Compartir Internet" en Mac, etc.
  O simplemente conecta tu PC y tu celular a la misma red WiFi de casa).
- No incluye detección por Bluetooth todavía (queda para un módulo aparte).
- No guarda nada en base de datos todavía (eso viene en la siguiente fase).

Requisitos:
    pip install scapy mac-vendor-lookup

Ejecutar:
    - Windows: correr la terminal como Administrador (y tener Npcap instalado,
      que scapy pide automáticamente si no lo tienes).
    - Linux/Mac: correr con sudo.

    python monitor_dispositivos.py
"""

import time
from datetime import datetime

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
    print("Aviso: mac_vendor_lookup no instalado (pip install mac-vendor-lookup)."
          " Se mostrará el fabricante como 'Desconocido'.\n")


# ============================================================
# CONFIGURACIÓN (edita esto según tu red)
# ============================================================

# Rango de red a escanear. Revisa tu IP local con:
#   Windows: ipconfig      Linux/Mac: ifconfig / ip a
# Si tu PC tiene IP 192.168.1.5, normalmente el rango es 192.168.1.0/24
RED_OBJETIVO = "192.168.1.0/24"

# Lista blanca de dispositivos autorizados. Agrega aquí la MAC real de tu
# celular de prueba (en mayúsculas) para verlo como AUTORIZADO.
DISPOSITIVOS_AUTORIZADOS = {
        "52:4F:DD:5F:2E:1F",
        "42:54:C7:B2:2B:BC"# <-- reemplaza con la MAC de tu celular
}

INTERVALO_ESCANEO_SEGUNDOS = 5


# ============================================================
# FUNCIONES
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

def imprimir_dispositivo(dispositivo: dict, es_nuevo: bool):
    hora = datetime.now().strftime("%H:%M:%S")
    estado = clasificar_estado(dispositivo["mac"])
    fabricante = obtener_fabricante(dispositivo["mac"])
    etiqueta = "[NUEVO]" if es_nuevo else "       "

    print(
        f"{etiqueta} {hora} | IP: {dispositivo['ip']:<15} "
        f"| MAC: {dispositivo['mac']:<17} "
        f"| Fabricante: {fabricante:<25} "
        f"| Estado: {estado}"
    )


def main():
    print("=" * 95)
    print("  MODULO DE DETECCION DE DISPOSITIVOS EN RED - Avance de Proyecto")
    print(f"  Red objetivo: {RED_OBJETIVO}")
    print("  Conecta tu celular a la misma red WiFi/hotspot para verlo aparecer aqui.")
    print("  Presiona Ctrl+C para detener.")
    print("=" * 95)

    dispositivos_vistos = set()

    try:
        while True:
            dispositivos = escanear_red(RED_OBJETIVO)

            if not dispositivos:
                print("No se detectaron dispositivos en este ciclo.")

            for d in dispositivos:
                es_nuevo = d["mac"] not in dispositivos_vistos
                if es_nuevo:
                    dispositivos_vistos.add(d["mac"])
                imprimir_dispositivo(d, es_nuevo)

            print(f"\nTotal detectados: {len(dispositivos)} | "
                  f"Esperando {INTERVALO_ESCANEO_SEGUNDOS}s...\n")
            time.sleep(INTERVALO_ESCANEO_SEGUNDOS)

    except KeyboardInterrupt:
        print("\nEscaneo detenido por el usuario.")


if __name__ == "__main__":
    main()
