import random
import pyperclip
import sqlite3
import hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial
import array
import sv_ttk
from tkinter import ttk
from ctypes import windll

def copyToClipboard(text):
    pyperclip.copy(text)
usergeneratedpwlen = 12  

def generator():
    # Source of the following function: https://www.geeksforgeeks.org/generating-strong-password-using-python/
    MAX_LEN = usergeneratedpwlen

    DIGITS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    LOCASE_CHARACTERS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                         'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q',
                         'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
                         'z']
    UPCASE_CHARACTERS = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                         'I', 'J', 'K', 'M', 'N', 'O', 'P', 'Q',
                         'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
                         'Z']

    SYMBOLS = ['@', '#', '$', '%', '=', ':', '?', '.', '/', '|', '~', '>',
               '*', '(', ')', '<']

    COMBINED_LIST = DIGITS + UPCASE_CHARACTERS + LOCASE_CHARACTERS + SYMBOLS

    rand_digit = random.choice(DIGITS)
    rand_upper = random.choice(UPCASE_CHARACTERS)
    rand_lower = random.choice(LOCASE_CHARACTERS)
    rand_symbol = random.choice(SYMBOLS)

    temp_pass = rand_digit + rand_upper + rand_lower + rand_symbol

    for x in range(int(MAX_LEN) - 4):
        temp_pass = temp_pass + random.choice(COMBINED_LIST)

        temp_pass_list = array.array('u', temp_pass)
        random.shuffle(temp_pass_list)
    global passwordg
    passwordg = ""
    for x in temp_pass_list:
        passwordg = passwordg + x



with sqlite3.connect("password_vault.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL
);
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL
);
""")


def popUp(text):
    answer = simpledialog.askstring("input string", text)
    return answer


window = Tk()
window.title("Passwords")
sv_ttk.set_theme("light")
windll.shcore.SetProcessDpiAwareness(1)

def hashPassword(input):
    hash = hashlib.sha3_512(input)
    hash = hash.hexdigest()
    return hash


def firstScreen():
    window.geometry("1050x570")

    lbl3 = ttk.Label(window, text="v0.3-beta")
    lbl3.config(anchor=CENTER)
    lbl3.pack()

    lbl = ttk.Label(window, text="Create Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = ttk.Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = ttk.Label(window, text="Re-enter Password")
    lbl1.pack()

    txt1 = ttk.Entry(window, width=20, show="*")
    txt1.pack()
    txt1.focus()

    lbl2 = ttk.Label(window)
    lbl2.pack()

    def savePassword():
        if txt.get() == txt1.get():
            minlength = 10
            length = (len(txt.get()))
            if length >= minlength:
                hashedPassword = hashPassword(txt.get().encode("utf-8"))

                insert_password = """INSERT INTO masterpassword(password)
                VALUES(?) """
                cursor.execute(insert_password, [(hashedPassword)])
                db.commit()
                passwordVault()
            else:
                lbl2.config(text="Too short password!")
        else:
            lbl2.config(text="Passwords do not match")

    btn = ttk.Button(window, text="Submit", command=savePassword)
    btn.pack(pady=10)


def loginScreen():
    window.geometry("700x380")

    lbl3 = ttk.Label(window, text="v0.3-beta")
    lbl3.config(anchor=CENTER)
    lbl3.pack()

    lbl2 = ttk.Label(window, text="Master password", font=("Helvetica", 12))
    lbl2.config(anchor=CENTER)
    lbl2.pack()
    txt = ttk.Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = ttk.Label(window)
    lbl1.pack()

    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode("utf-8"))
        cursor.execute(
            "SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(checkHashedPassword)])

        return cursor.fetchall()

    def checkPassword():
        match = getMasterPassword()

        if match:
            passwordVault()
        else:
            txt.delete(0, "end")
            lbl1.config(text="Wrong Password")

    btn = ttk.Button(window, text="Submit", command=checkPassword)
    btn.pack(pady=10)


def passwordVault():
    for widget in window.winfo_children():
        widget.destroy()

    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()

        passwordVault()
    window.geometry("1250x600")

    lbl = ttk.Label(window, text="Password Vault", font=("Helvetica", 16))
    lbl.grid(column=0)
    lbl4 = ttk.Label(window, text="Add number to generator", font=("Helvetica", 12))
    lbl4.grid(column=0, row=1)

    def pwgeneratorsettings():
        lenlist = [10, 12, 14, 16, 18, 20]
        value = StringVar(window)

        def send_answer():
            global usergeneratedpwlen
            usergeneratedpwlen = format(value.get())
            lbl4.config(text="")
            lbl4.grid(column=0, row=1)
            return None
        om = ttk.OptionMenu(window, value, *lenlist)
        om.grid(column=2, row=0)
        submit_button = ttk.Button(window, text='Submit', command=send_answer)
        submit_button.grid(column=2, row=1)
        

    pwgeneratorsettings()

    def addEntry():
        generator()
        text1 = "Website"
        text2 = "Username"
        text3 = "Password", passwordg

        website = popUp(text1)
        username = popUp(text2)
        password = popUp(text3)
        insert_fields = """INSERT INTO vault(website,username,password)
        VALUES(?, ?, ?)"""

        cursor.execute(insert_fields, (website, username, password))
        db.commit()
        passwordVault()
    btn = ttk.Button(window, text="+", command=addEntry)
    btn.grid(column=1, pady=10)

    lbl = ttk.Label(window, text="Website", font=("Helvetica", 16))
    lbl.grid(row=3, column=0, padx=100)
    lbl = ttk.Label(window, text="Username", font=("Helvetica", 16))
    lbl.grid(row=3, column=1, padx=100)
    lbl = ttk.Label(window, text="Password", font=("Helvetica", 16))
    lbl.grid(row=3, column=2, padx=100)


    cursor.execute("SELECT * FROM vault")
    vault_entries = cursor.fetchall()
    if vault_entries:
        for i in range(len(vault_entries)):

            lbl1 = ttk.Label(window, text=(vault_entries[i][1]), font=("Helvetica", 16))
            lbl1.grid(column=0, row=i+4)
            lbl1 = ttk.Label(window, text=(vault_entries[i][2]), font=("Helvetica", 16))
            lbl1.grid(column=1, row=i+4)
            btn_copy_username = ttk.Button(window, text="Copy username", command=lambda text=vault_entries[i][2]: copyToClipboard(text))
            btn_copy_username.grid(column=5, row=i+4)

            lbl_password = ttk.Label(window, text="*" * len(vault_entries[i][3]), font=("Helvetica", 16))
            lbl_password.grid(column=2, row=i+4)
            btn_copy_password = ttk.Button(window, text="Copy password", command=lambda text=vault_entries[i][3]: copyToClipboard(text))
            btn_copy_password.grid(column=6, row=i+4)    

            def showPassword(i, lbl=lbl_password):
                lbl.config(text=(vault_entries[i][3]))

                def hidePassword():
                    lbl.config(text="*" * len(vault_entries[i][3]))

                window.after(10000, hidePassword)

            btn_show = ttk.Button(window, text="Show", command=lambda i=i, lbl=lbl_password: showPassword(i, lbl))
            btn_show.grid(column=3, row=i+4, pady=10)
            btn_delete = ttk.Button(window, text="Delete", command=partial(removeEntry, vault_entries[i][0]))
            btn_delete.grid(column=4, row=i+4, pady=10)


cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()
window.mainloop()
