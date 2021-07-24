import random
import string
import sqlite3
import hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial
import array
# Generator


def generator():
    MAX_LEN = usergeneratedpwlen

    # declare arrays of the character that we need in out password
    # Represented as chars to enable easy string concatenation
    DIGITS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    LOCASE_CHARACTERS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                         'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q',
                         'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
                         'z']

    UPCASE_CHARACTERS = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                         'I', 'J', 'K', 'M', 'N', 'O', 'p', 'Q',
                         'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
                         'Z']

    SYMBOLS = ['@', '#', '$', '%', '=', ':', '?', '.', '/', '|', '~', '>',
               '*', '(', ')', '<']

    # combines all the character arrays above to form one array
    COMBINED_LIST = DIGITS + UPCASE_CHARACTERS + LOCASE_CHARACTERS + SYMBOLS

    # randomly select at least one character from each character set above
    rand_digit = random.choice(DIGITS)
    rand_upper = random.choice(UPCASE_CHARACTERS)
    rand_lower = random.choice(LOCASE_CHARACTERS)
    rand_symbol = random.choice(SYMBOLS)

    # combine the character randomly selected above
    # at this stage, the password contains only 4 characters but
    # we want a 12-character password
    temp_pass = rand_digit + rand_upper + rand_lower + rand_symbol

    # now that we are sure we have at least one character from each
    # set of characters, we fill the rest of
    # the password length by selecting randomly from the combined
    # list of character above.
    for x in range(int(MAX_LEN) - 4):
        temp_pass = temp_pass + random.choice(COMBINED_LIST)

        # convert temporary password into array and shuffle to
        # prevent it from having a consistent pattern
        # where the beginning of the password is predictable
        temp_pass_list = array.array('u', temp_pass)
        random.shuffle(temp_pass_list)
    global passwordg
    # traverse the temporary password array and append the chars
    # to form the password
    passwordg = ""
    for x in temp_pass_list:
        passwordg = passwordg + x


# Database
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

# Create POPUP


def popUp(text):
    answer = simpledialog.askstring("input string", text)
    return answer


# Initiate Window
window = Tk()
window.title("Password Vault")


def hashPassword(input):
    hash = hashlib.sha3_512(input)
    hash = hash.hexdigest()
    return hash


def firstScreen():
    window.geometry("350x150")

    lbl = Label(window, text="Create Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window, text="Re-enter Password")
    lbl1.pack()

    txt1 = Entry(window, width=20, show="*")
    txt1.pack()
    txt1.focus()

    lbl2 = Label(window)
    lbl2.pack()

    def savePassword():
        if txt.get() == txt1.get():
            minlength = 10
            lenght = (len(txt.get()))
            if minlength > lenght:
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

    btn = Button(window, text="Submit", command=savePassword)
    btn.pack(pady=10)


def loginScreen():
    window.geometry("350x150")

    lbl = Label(window)
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
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

    btn = Button(window, text="Submit", command=checkPassword)
    btn.pack(pady=10)


def passwordVault():
    for widget in window.winfo_children():
        widget.destroy()

    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()

        passwordVault()
    window.geometry("700x350")

    lbl = Label(window, text="Password Vault")
    lbl.grid(column=0)

    def pwgeneratorsettings():
        lenlist = [10, 12, 14, 16, 18, 20]
        value = StringVar(window)

        def send_answer():
            global usergeneratedpwlen
            usergeneratedpwlen = format(value.get())
            return None
        dd = OptionMenu(window, value, *lenlist)
        dd.grid(column=2, row=0)
        submit_button = Button(window, text='Submit', command=send_answer)
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
    btn = Button(window, text="+", command=addEntry)
    btn.grid(column=1, pady=10)

    lbl = Label(window, text="Website")
    lbl.grid(row=3, column=0, padx=80)
    lbl = Label(window, text="Username")
    lbl.grid(row=3, column=1, padx=80)
    lbl = Label(window, text="Password")
    lbl.grid(row=3, column=2, padx=80)

    cursor.execute("SELECT * FROM vault")
    if(cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()

            lbl1 = Label(window, text=(array[i][1]), font=("Helvetica", 12))
            lbl1.grid(column=0, row=i+4)
            lbl1 = Label(window, text=(array[i][2]), font=("Helvetica", 12))
            lbl1.grid(column=1, row=i+4)
            lbl1 = Label(window, text=(array[i][3]), font=("Helvetica", 12))
            lbl1.grid(column=2, row=i+4)

            btn = Button(window, text="Delete",
                         command=partial(removeEntry, array[i][0]))
            btn.grid(column=3, row=i+4, pady=10)

            i = i+1

            cursor.execute("SELECT * FROM vault")
            if(len(cursor.fetchall()) <= i):
                break


cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()
window.mainloop()
