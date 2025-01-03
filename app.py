import customtkinter as ctk
import requests
from tkinter import filedialog, messagebox
import os
import time
import threading
from PIL import Image, ImageTk

# Ganti dengan API key VirusTotal Anda
API_KEY = "(API KEY VIRUS TOTAL ANDA)"

def validate_api_key():
    url = "https://www.virustotal.com/api/v3/users/me"
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return True
        else:
            messagebox.showerror("Error", f"API Key Invalid: {response.json()}")
            return False
    except Exception as e:
        messagebox.showerror("Error", f"Gagal memvalidasi API Key: {e}")
        return False

def upload_file_to_virustotal(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": API_KEY}
    try:
        with open(file_path, "rb") as file:
            files = {"file": (os.path.basename(file_path), file)}
            response = requests.post(url, headers=headers, files=files)
        
        if response.status_code == 200:
            file_id = response.json()["data"]["id"]
            return file_id
        else:
            messagebox.showerror("Error", f"Gagal mengunggah file: {response.json()}")
            return None
    except Exception as e:
        messagebox.showerror("Error", f"Kesalahan saat mengunggah file: {e}")
        return None

def get_scan_results(file_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
    headers = {"x-apikey": API_KEY}
    try:
        while True:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                analysis = response.json()["data"]["attributes"]
                status = analysis["status"]
                if status == "completed":
                    return analysis["stats"]
                else:
                    time.sleep(3)
            else:
                messagebox.showerror("Error", f"Gagal mendapatkan hasil analisis: {response.json()}")
                return None
    except Exception as e:
        messagebox.showerror("Error", f"Kesalahan saat mengambil hasil scan: {e}")
        return None

def delete_file(file_path):
    try:
        os.remove(file_path)
        messagebox.showinfo("Info", f"File {file_path} berhasil dihapus.")
    except Exception as e:
        messagebox.showerror("Error", f"Gagal menghapus file: {e}")

def scan_file():
    if not validate_api_key():
        return

    file_path = filedialog.askopenfilename(title="Pilih File untuk Di-Scan")
    if not file_path:
        return

    def process_scan():
        result_label.configure(text="🔄 Sedang mengunggah file...")
        progress_bar.set(0.2)
        app.update()

        file_id = upload_file_to_virustotal(file_path)
        if file_id:
            result_label.configure(text="🔄 Menunggu hasil analisis...")
            progress_bar.set(0.6)
            app.update()

            result = get_scan_results(file_id)
            if result:
                malicious = result.get("malicious", 0)
                harmless = result.get("harmless", 0)

                if malicious > 0:
                    status = "⚠️ File TERINDIKASI BERBAHAYA!"
                    color = "red"
                else:
                    status = "✅ File AMAN. Tidak ditemukan indikasi malware."
                    color = "green"

                result_text = f"""
File: {os.path.basename(file_path)}
Harmless: {harmless}
Malicious: {malicious}
Status: {status}
"""
                result_box.configure(text=result_text, text_color=color)
                progress_bar.set(1.0)

                if messagebox.askyesno("Konfirmasi", "Apakah Anda ingin menghapus file setelah scan selesai?"):
                    delete_file(file_path)
            else:
                result_label.configure(text="❌ Gagal mendapatkan hasil analisis.", text_color="red")
        else:
            result_label.configure(text="❌ Gagal mengunggah file ke VirusTotal.", text_color="red")
            progress_bar.set(0)

    scan_thread = threading.Thread(target=process_scan)
    scan_thread.start()

def exit_app():
    app.quit()

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("AntiVirus Kompe - ELKartel")
app.geometry("700x500")

icon_image = Image.open("Firefly.jpg")
icon_photo = ImageTk.PhotoImage(icon_image.resize((60, 60)))
icon_label = ctk.CTkLabel(app, image=icon_photo, text="")
icon_label.pack(pady=(20, 10))

title_label = ctk.CTkLabel(app, text="Antivirus Kompe", font=("Helvetica", 24, "bold"))
title_label.pack()

progress_bar = ctk.CTkProgressBar(app, width=400)
progress_bar.set(0)
progress_bar.pack(pady=20)

scan_button = ctk.CTkButton(app, text="Pilih File & Scan", command=scan_file, font=("Helvetica", 14), fg_color="#3B82F6", hover_color="#2563EB", height=40)
scan_button.pack(pady=10)

result_label = ctk.CTkLabel(app, text="Pilih file untuk memulai scan.", font=("Helvetica", 14))
result_label.pack(pady=(10, 5))

result_box = ctk.CTkLabel(app, text="", font=("Helvetica", 14), justify="left", wraplength=600, height=150, fg_color="#f1f5f9", corner_radius=10, text_color="black")
result_box.pack(pady=10, padx=20, fill="both")

exit_button = ctk.CTkButton(app, text="Keluar", command=exit_app, font=("Helvetica", 14), fg_color="#EF4444", hover_color="#B91C1C", height=40)
exit_button.pack(pady=20)

app.mainloop()
