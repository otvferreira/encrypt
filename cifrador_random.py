import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk, ImageFile
# Permitir carregar imagens truncadas
ImageFile.LOAD_TRUNCATED_IMAGES = True
import os, tempfile

# IMPORTA O MÓDULO ESCOLHIDO: altere entre 'cifrador_arvore' ou 'cifrador_random'
from cifrador_arvore import cifragem, decifragem
# from cifrador_random import cifragem, decifragem

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cifrador de Imagens PBM")
        self.geometry("600x550")
        
        # Entrada de imagem
        tk.Label(self, text="Imagem (.pbm/.pgm/.ppm):").pack(anchor='w', padx=10, pady=(10,0))
        frame_img = tk.Frame(self); frame_img.pack(fill='x', padx=10)
        self.entry_image = tk.Entry(frame_img)
        self.entry_image.pack(side='left', fill='x', expand=True)
        tk.Button(frame_img, text="Selecionar...", command=self.select_image).pack(side='left', padx=5)

        # Entrada de chave
        tk.Label(self, text="Chave (128 bytes):").pack(anchor='w', padx=10, pady=(10,0))
        frame_key = tk.Frame(self); frame_key.pack(fill='x', padx=10)
        self.entry_key = tk.Entry(frame_key)
        self.entry_key.pack(side='left', fill='x', expand=True)
        tk.Button(frame_key, text="Selecionar...", command=self.select_key).pack(side='left', padx=5)

        # Botões de ação
        frame_btn = tk.Frame(self); frame_btn.pack(pady=10)
        tk.Button(frame_btn, text="Cifrar",   command=self.on_cifrar).pack(side='left', padx=5)
        tk.Button(frame_btn, text="Decifrar", command=self.on_decifrar).pack(side='left', padx=5)

        # Área de exibição
        self.image_label = tk.Label(self); self.image_label.pack(pady=10)
        self.temp_dir = tempfile.mkdtemp()

    def select_image(self):
        file = filedialog.askopenfilename(filetypes=[("Imagens NetPBM", "*.pbm *.pgm *.ppm")])
        if file:
            self.entry_image.delete(0, tk.END)
            self.entry_image.insert(0, file)
            try: self.show_image(file)
            except: pass

    def select_key(self):
        file = filedialog.askopenfilename(filetypes=[("Arquivos binários","*")])
        if file:
            self.entry_key.delete(0, tk.END)
            self.entry_key.insert(0, file)

    def on_cifrar(self):
        img, key = self.entry_image.get().strip(), self.entry_key.get().strip()
        if not os.path.isfile(img) or not os.path.isfile(key):
            return messagebox.showerror("Erro","Imagem ou chave inválida")
        out = os.path.join(self.temp_dir, 'cifrada'+os.path.splitext(img)[1])
        try:
            cifragem(img, out, key)
            self.entry_image.delete(0, tk.END); self.entry_image.insert(0, out)
            messagebox.showinfo("Sucesso", f"Imagem cifrada: {out}")
        except Exception as e:
            messagebox.showerror("Erro", str(e))

    def on_decifrar(self):
        img, key = self.entry_image.get().strip(), self.entry_key.get().strip()
        if not os.path.isfile(img) or not os.path.isfile(key):
            return messagebox.showerror("Erro","Imagem ou chave inválida")
        out = os.path.join(self.temp_dir, 'decifrada'+os.path.splitext(img)[1])
        try:
            decifragem(img, out, key)
            self.entry_image.delete(0, tk.END); self.entry_image.insert(0, out)
            self.show_image(out)
        except Exception as e:
            messagebox.showerror("Erro", str(e))

    def show_image(self, path):
        img = Image.open(path)
        img.thumbnail((550,450))
        self.photo = ImageTk.PhotoImage(img)
        self.image_label.config(image=self.photo)

if __name__=='__main__':
    App().mainloop()