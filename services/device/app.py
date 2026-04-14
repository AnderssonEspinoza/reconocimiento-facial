import os
import threading
import time

from flask import Flask, jsonify, request
import serial
import serial.tools.list_ports

SERIAL_BAUDRATE = int(os.getenv("SERIAL_BAUDRATE", "9600"))
ARDUINO_PORT = os.getenv("ARDUINO_PORT", "").strip()
PUERTOS_CANDIDATOS = ["/dev/ttyUSB0", "/dev/ttyACM0", "COM3", "COM4", "COM5"]


class ArduinoSerial:
    def __init__(self, baudrate=SERIAL_BAUDRATE, preferred_port=""):
        self.baudrate = baudrate
        self.preferred_port = preferred_port
        self.serial_conn = None
        self.port = None
        self.last_connect_attempt = 0.0
        self.last_message = None
        self.lock = threading.Lock()

    def _puertos_disponibles(self):
        ports = [p.device for p in serial.tools.list_ports.comports()]
        ordered = []
        if self.preferred_port:
            ordered.append(self.preferred_port)
        for p in PUERTOS_CANDIDATOS:
            if p not in ordered:
                ordered.append(p)
        for p in ports:
            if p not in ordered:
                ordered.append(p)
        return ordered

    def connect(self):
        now = time.time()
        if now - self.last_connect_attempt < 2:
            return False
        self.last_connect_attempt = now

        for port in self._puertos_disponibles():
            try:
                conn = serial.Serial(port=port, baudrate=self.baudrate, timeout=1)
                time.sleep(2.0)
                self.serial_conn = conn
                self.port = port
                return True
            except Exception:
                continue
        return False

    def ensure_connected(self):
        if self.serial_conn and self.serial_conn.is_open:
            return True
        return self.connect()

    def write_line(self, msg):
        with self.lock:
            if not self.ensure_connected():
                return False, "Arduino no conectado"
            try:
                self.serial_conn.write((msg + "\n").encode("utf-8"))
                self.last_message = msg
                return True, f"Mensaje enviado por {self.port}"
            except Exception as exc:
                try:
                    self.serial_conn.close()
                except Exception:
                    pass
                self.serial_conn = None
                self.port = None
                return False, f"Fallo serial: {exc}"

    def status(self):
        connected = self.ensure_connected()
        return {
            "connected": connected,
            "port": self.port,
            "last_message": self.last_message,
            "baudrate": self.baudrate,
        }


arduino = ArduinoSerial(preferred_port=ARDUINO_PORT)
app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "device-service"})


@app.get("/status")
def status():
    st = arduino.status()
    return jsonify(st)


@app.post("/notify")
def notify():
    payload = request.get_json(silent=True) or {}
    text = str(payload.get("text", "")).strip()
    if not text:
        return jsonify({"ok": False, "info": "text vacio"}), 400

    ok, info = arduino.write_line(text)
    return jsonify({
        "ok": ok,
        "info": info,
        "port": arduino.port,
        "message": text,
        "led_on": bool(payload.get("led_on", False)),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001, debug=False, threaded=True)
