import tkinter as tk
from tkinter import filedialog,messagebox,simpledialog
from tkinter.ttk import Progressbar
import os
import hashlib,base64,threading
from cryptography.fernet import Fernet,InvalidToken

class EncryptDecryptApp:
    def __init__(self,root):
        self.root=root
        self.active_button="e"
        self.icon_path="icon.ico"
        self.image_path='key.gif'
        root.title("  File Encrypter and Decrypter")
        try:
            root.iconbitmap(default=self.icon_path)
        except Exception as e:
            pass
        root.geometry("1000x600+0+0")
        root.configure(bg="#08CF9C")
        root.bind("<KeyPress>",self.on_key_press)
        try:
            photo=tk.PhotoImage(file=self.image_path)
            label=tk.Label(root,image=photo)
            label.pack(pady=(20,0),fill=tk.BOTH,padx=30)
        except Exception as e:
            pass

        self.encrypt_button=tk.Button(root,text="ENCRYPT",bg="green",width=12,height=3,font=("Arial",15,"bold"),command=lambda:self.open_file_dialog("e"))
        self.decrypt_button=tk.Button(root,text="DECRYPT",bg="cyan",width=12,height=3,font=("Arial",15,"bold"),command=lambda:self.open_file_dialog("d"))

        self.encrypt_button.bind("<Enter>",self.on_enter)
        
        self.decrypt_button.bind("<Enter>",self.on_enter)

        self.encrypt_button.pack(pady=20,padx=30,fill=tk.BOTH)
        self.decrypt_button.pack(padx=30,fill=tk.BOTH)

        root.mainloop()

    def toggle_buttons(self):
        if(self.active_button=="e"):
            self.active_button="d"
            self.decrypt_button.configure(bg="green")
            self.encrypt_button.configure(bg="cyan")
        else:
            self.active_button="e"
            self.decrypt_button.configure(bg="cyan")
            self.encrypt_button.configure(bg="green")



    def on_key_press(self,event):
        if(event.keycode==27):
            self.root.destroy()
        elif(event.keycode==38): #up arrow
            self.toggle_buttons()
        elif(event.keycode==40): #down arrow
            self.toggle_buttons()
        elif(event.keycode==13): #enter button
            self.open_file_dialog(self.active_button)

    def on_enter(self,event):
        button=event.widget
        if(event.widget.cget("text")=="ENCRYPT"):
            self.active_button="e"
            self.encrypt_button.configure(bg="green")
            self.decrypt_button.configure(bg="cyan")
        else:
            self.active_button="d"
            self.encrypt_button.configure(bg="cyan")
            self.decrypt_button.configure(bg="green") 
   

    
    def open_file_dialog(self,button):
        try:
            if(button=="e"):
                file_path=filedialog.askopenfilename(title="Select File To Encrypt",filetypes=[("All Files","*.*")])
                file_name=os.path.basename(file_path)
                if(".enc" in file_name):
                    messagebox.showerror(title="Error",message="Already Encrypted !!")
                    return
                
                if file_path:
                    password=simpledialog.askstring("Password","Create Password",show="*")
                    if password is None:
                        messagebox.showerror(title="Error",message="Please,Enter A Password!!")
                        
                    else:
                        threading.Thread(target=self.encrypt(file_path,password)).start()
                else:
                    messagebox.showerror(title="Error",message="Please,Select A File !!")
                
            else: 
                file_path=filedialog.askopenfilename(title="Select File To Decrypt",filetypes=[("Encrypted Files","*.enc")])
                if file_path:
                    password=simpledialog.askstring("Password","Enter Password",show="*")
                    if password is None:
                        messagebox.showerror(title="Error",message="Please,Enter A Password!!")
                    else:
                        threading.Thread(target=self.decrypt(file_path,password)).start()
                else:
                    messagebox.showerror(title="Error",message="Please,Select A File !!")
        except Exception as e:
            messagebox.showerror(title="Error",message=str(e))


    def encrypt(self,file_path,password):
        try:
            progress_bar=Progressbar(self.root,length=200,mode="indeterminate")
            progress_bar.place(x=500,y=300)
            progress_bar.start(5)
            key=hashlib.sha256(password.encode("utf-8")).hexdigest()[:32]
            key=base64.b64encode(key.encode("utf-8"))
            cipher=Fernet(key)
            with open(file_path,"rb") as f:
                data=f.read()
            encrypted_data=cipher.encrypt(data)
            with open(file_path+".enc","wb") as f:
                f.write(encrypted_data)
            os.system(f"attrib +R {file_path}.enc")
            os.remove(file_path)
            progress_bar.stop()
            progress_bar.destroy()
            messagebox.showinfo(title="Success",message="File Encrypted Successfully !!")
          
        except Exception as e:
            progress_bar.stop()
            progress_bar.destroy()
            messagebox.showerror(title="Error",message=str(e))
       

    def decrypt(self,file_path,password):
        try:
            progress_bar=Progressbar(self.root,length=200,mode="indeterminate")
            progress_bar.place(x=500,y=300)
            progress_bar.start(5)
            key=hashlib.sha256(password.encode("utf-8")).hexdigest()[:32]
            key=base64.b64encode(key.encode("utf-8"))
            
            cipher=Fernet(key)
            
            os.system(f"attrib -R {file_path}")
            with open(file_path,"rb") as f:
                data=f.read()
            decrypted_data=cipher.decrypt(data)
            with open(file_path[:-4],"wb") as f:
                f.write(decrypted_data)
            os.remove(file_path)
            progress_bar.stop()
            progress_bar.destroy()
            messagebox.showinfo(title="Success",message="File Decrypted Successfully !!")
        
        except InvalidToken as e:
            progress_bar.stop()
            progress_bar.destroy()
            messagebox.showerror(title="Error",message="Wrong Password !!")
        except Exception as e:
            progress_bar.stop()
            progress_bar.destroy()
            messagebox.showerror(title="Error",message=str(e))




if __name__=="__main__":
    window=tk.Tk()
    app=EncryptDecryptApp(window)
