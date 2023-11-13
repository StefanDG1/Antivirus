from customtkinter import *
from os import *


# initializing the customtkinter app window and giving it dimensions and a title
app = CTk()
app.geometry("800x600")
app.title("Antivirus")

# creating an empty string and tuple where the dir and filenames will be stored
dirname = ''
filenames = ()

# function to open the dialog box to select a directory and stores it in the dirname string
def dir_dialog():
    dirname = filedialog.askdirectory()
    print(dirname)
    dir_label.configure(text=f"Selected directory: {dirname}")

# function to open the dialog box to select filenames and stores it in the dirname tuple
def filenames_dialog():
    filenames = filedialog.askopenfilenames()
    print(filenames)
    file_label.configure(text=f"Selected files: {filenames}")

# creating the buttons with their correct commands and placing them in the window, as well as their labels
dir_btn = CTkButton(app, text="Select Directory", command=dir_dialog)
dir_btn.place(relx=0.5, rely=0.5, anchor="center")
dir_label = CTkLabel(app, text="Selected directory:", fg_color="transparent")
dir_label.place(relx=0.5, rely=0.55, anchor="center")

file_btn = CTkButton(app, text="Select Files", command=filenames_dialog)
file_btn.place(relx=0.5, rely=0.6, anchor="center")
file_label = CTkLabel(app, text="Selected files:", fg_color="transparent")
file_label.place(relx=0.5, rely=0.65, anchor="center")


app.mainloop()