import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk, ImageFile
# Permitir carregar imagens truncadas
ImageFile.LOAD_TRUNCATED_IMAGES = True
import os
import tempfile

# Importa funções de cifragem/decifragem do módulo cifrador_pbm
from cifrador_pbm import cifragem, decifragem

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cifrador de Imagens PBM")
        self.geometry("600x550")

        # Entrada de imagem
        tk.Label(self, text="Imagem (.pbm/.pgm/.ppm):").pack(anchor='w', padx=10, pady=(10,0))
        frame_img = tk.Frame(self)
        frame_img.pack(fill='x', padx=10)
        self.entry_image = tk.Entry(frame_img)
        self.entry_image.pack(side='left', fill='x', expand=True)
        tk.Button(frame_img, text="Selecionar...", command=self.select_image).pack(side='left', padx=(5,0))

        # Entrada de chave
        tk.Label(self, text="Chave (128 bytes):").pack(anchor='w', padx=10, pady=(10,0))
        frame_key = tk.Frame(self)
        frame_key.pack(fill='x', padx=10)
        self.entry_key = tk.Entry(frame_key)
        self.entry_key.pack(side='left', fill='x', expand=True)
        tk.Button(frame_key, text="Selecionar...", command=self.select_key).pack(side='left', padx=(5,0))

        # Botões de ação
        frame_btn = tk.Frame(self)
        frame_btn.pack(pady=10)
        tk.Button(frame_btn, text="Cifrar", command=self.on_cifrar).pack(side='left', padx=5)
        tk.Button(frame_btn, text="Decifrar", command=self.on_decifrar).pack(side='left', padx=5)

        # Área de exibição da imagem
        self.image_label = tk.Label(self)
        self.image_label.pack(pady=10)

        # Diretório temporário para arquivos resultantes
        self.temp_dir = tempfile.mkdtemp()

    def select_image(self):
        file = filedialog.askopenfilename(
            filetypes=[("Imagens NetPBM", "*.pbm *.pgm *.ppm")]
        )
        if file:
            self.entry_image.delete(0, tk.END)
            self.entry_image.insert(0, file)
            # Exibe imediatamente a imagem original
            try:
                self.show_image(file)
            except Exception:
                pass

    def select_key(self):
        file = filedialog.askopenfilename(
            filetypes=[("Arquivos binários", "*")]
        )
        if file:
            self.entry_key.delete(0, tk.END)
            self.entry_key.insert(0, file)

    def on_cifrar(self):
        img_path = self.entry_image.get().strip()
        key_path = self.entry_key.get().strip()
        if not os.path.isfile(img_path) or not os.path.isfile(key_path):
            messagebox.showerror("Erro", "Imagem ou chave inválida")
            return
        out_path = os.path.join(self.temp_dir, 'cifrada' + os.path.splitext(img_path)[1])
        try:
            cifragem(img_path, out_path, key_path)
            # Atualiza entrada para arquivo cifrado
            self.entry_image.delete(0, tk.END)
            self.entry_image.insert(0, out_path)
            messagebox.showinfo("Sucesso", f"Imagem cifrada salva em:\n{out_path}")
        except Exception as e:
            messagebox.showerror("Erro", str(e))

    def on_decifrar(self):
        img_path = self.entry_image.get().strip()
        key_path = self.entry_key.get().strip()
        if not os.path.isfile(img_path) or not os.path.isfile(key_path):
            messagebox.showerror("Erro", "Imagem ou chave inválida")
            return
        out_path = os.path.join(self.temp_dir, 'decifrada' + os.path.splitext(img_path)[1])
        try:
            decifragem(img_path, out_path, key_path)
            # Atualiza entrada e exibe imagem decifrada
            self.entry_image.delete(0, tk.END)
            self.entry_image.insert(0, out_path)
            self.show_image(out_path)
        except Exception as e:
            messagebox.showerror("Erro", str(e))

    def show_image(self, path):
        # Abre com PIL e exibe via PhotoImage
        try:
            img = Image.open(path)
            img.thumbnail((550, 450))
            self.photo = ImageTk.PhotoImage(img)
            self.image_label.config(image=self.photo)
        except Exception as e:
            messagebox.showerror("Erro ao exibir imagem", f"Não foi possível exibir a imagem:\n{e}")

if __name__ == '__main__':
    app = App()
    app.mainloop()
