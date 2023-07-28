import sqlite3, hashlib, string, random, re
from tkinter import *
from tkinter import simpledialog, messagebox
from functools import partial
import pyperclip  # Library to interact with the clipboard


# database code
# Create two tables in the database to store master password and vault entries.
# The 'masterpassword' table stores the hashed master password.
# The 'vault' table stores website, username, and password entries.
with sqlite3.connect('password_vault.db') as db:
    cursor = db.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")

# Function to generate a strong password with given criteria and copy it to clipboard.
def generateStrongPassword():
    # Define your criteria for a strong password. For example, length and complexity.
    password_length = 12
    special_characters = "!@#$%^&*()_-+=[]{}|;:,.<>?/"
    password_characters = string.ascii_letters + string.digits + special_characters
    strong_password = ''.join(random.choice(password_characters) for i in range(password_length))
    pyperclip.copy(strong_password)
    messagebox.showinfo("Generated", "Strong password copied to clipboard.")

# Function to create a pop-up dialog to get user input.
def popUp(text):
    answer = simpledialog.askstring("input string", text)
    print(answer)
    return answer


# Create the main window.
window = Tk()
window.update()
window.title("Password Vault")

# Function to hash a given password using MD5.
def hashPassword(input):
    hash1 = hashlib.md5(input)
    hash1 = hash1.hexdigest()
    return hash1

# Function for the first time setup screen to create a master password.
def firstTimeScreen():
    window.geometry('250x125')
    window.resizable(False, False)
    lbl = Label(window, text="Choose a Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()
    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()
    lbl1 = Label(window, text="Re-enter password")
    lbl1.config(anchor=CENTER)
    lbl1.pack()
    txt1 = Entry(window, width=20, show="*")
    txt1.pack()

    def savePassword():
        if txt.get() == txt1.get():
            hashedPassword = hashPassword(txt.get().encode('utf-8'))

            insert_password = """INSERT INTO masterpassword(password)
            VALUES(?) """
            cursor.execute(insert_password, [(hashedPassword)])
            db.commit()
            vaultScreen()
        else:
            lbl.config(text="Passwords don't match")

    btn = Button(window, text="Save", background="gray" , command=savePassword)
    btn.pack(pady=5)

# Function for the login screen to enter the master password.
def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry('250x125')
    window.resizable(False, False)
    lbl = Label(window, text="Enter Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()
    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()
    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack(side=TOP)


    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1 AND password = ?', [(checkHashedPassword)])
        return cursor.fetchall()

    def checkPassword():
        password = getMasterPassword()
        if password:
            vaultScreen()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Wrong Password")

    btn = Button(window, text="Submit",background="gray", command=checkPassword)
    btn.pack(pady=5)

# Function to check the strength of a password based on certain criteria.
def check_password_strength(password):
    # Implement your password strength-checking logic here.
    # You can use any criteria you want to determine the password strength.
    # For example, you might consider length, complexity, and the presence of special characters.

    # For demonstration purposes, let's use a simple criterion: password length.
    length_error = len(password) < 8
    uppercase_error = not re.search(r"[A-Z]", password)
    lowercase_error = not re.search(r"[a-z]", password)
    digit_error = not re.search(r"\d", password)
    special_char_error = not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)

    errors = []

    if length_error:
        errors.append("Password must be at least 8 characters long.")
    if uppercase_error:
        errors.append("Password must contain at least one uppercase letter.")
    if lowercase_error:
        errors.append("Password must contain at least one lowercase letter.")
    if digit_error:
        errors.append("Password must contain at least one digit.")
    if special_char_error:
        errors.append("Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>).")

    if len(errors) == 0:
        return "Strong"
    elif len(errors) <= 2:
        return "Medium"
    else:
        return "Weak"

# Function for the main vault screen.
def vaultScreen():
    for widget in window.winfo_children():
        widget.destroy()

    def addEntry():
        # Prompt the user to enter website, username, and password using pop-up dialogs.

        text1 = "Website"
        text2 = "Username"
        text3 = "Password"
        website = popUp(text1)
        username = popUp(text2)
        password = popUp(text3)

        # Insert the entered website, username, and password into the 'vault' table in the database.

        insert_fields = """INSERT INTO vault(website, username, password) 
        VALUES(?, ?, ?) """
        cursor.execute(insert_fields, (website, username, password))
        db.commit()
        vaultScreen()

    def removeEntry(input):
        # Retrieve the password associated with the provided 'input' (ID) from the 'vault' table.

        cursor.execute("SELECT password FROM vault WHERE id = ?", (input,))
        password = cursor.fetchone()[0]
        # Delete the entry with the provided 'input' (ID) from the 'vault' table in the database.
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        vaultScreen()

        # Remove the password from the clipboard if it's deleted.
        pyperclip.copy("")  # Empty the clipboard

    def check_strength():
        password = popUp("Enter Password to Check Strength:")
        strength = check_password_strength(password)

        # Check if the password has been reused
        cursor.execute('SELECT * FROM vault WHERE password = ?', (password,))
        existing_entry = cursor.fetchone()

        if existing_entry:
            message = f"Password Strength: {strength}\nPassword is being reused"
            messagebox.showinfo("Password Strength", message)
        else:
            message = f"Password Strength: {strength}\nPassword was never used"
            messagebox.showinfo("Password Strength", message)


    def copyToClipboard(password):
        pyperclip.copy(password)
        messagebox.showinfo("Copied", "Password copied to clipboard.")

    window.geometry('750x550')
    window.resizable(False, False)

    btn_check_strength = Button(window, text="Check Strength",background="gray", command=check_strength)
    btn_check_strength.grid(row=0, column=0, padx=10, pady=30)

    btn_generate_password = Button(window, text="Generate Strong Password", background="gray",command=generateStrongPassword)
    btn_generate_password.grid(row=0, column=2, padx=10, pady=30)

    btn = Button(window, text="Add new login",background="gray", command=addEntry)
    btn.grid(row=0, column=1, padx=10, pady=30)
    lbl = Label(window, text="Website")
    lbl.grid(row=2, column=0, padx=80)
    lbl = Label(window, text="Username")
    lbl.grid(row=2, column=1, padx=80)
    lbl = Label(window, text="Password")
    lbl.grid(row=2, column=2, padx=80)
    cursor.execute('SELECT * FROM vault')
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute('SELECT * FROM vault')
            array = cursor.fetchall()

            if (len(array) == 0):
                break

            lbl1 = Label(window, text=(array[i][1]), font=("Helvetica", 12))
            lbl1.grid(column=0, row=(i + 3))
            lbl2 = Label(window, text=(array[i][2]), font=("Helvetica", 12))
            lbl2.grid(column=1, row=(i + 3))
            lbl3 = Label(window, text=(array[i][3]), font=("Helvetica", 12))
            lbl3.grid(column=2, row=(i + 3))
            btn_delete = Button(window, text="Delete",background="gray", command=partial(removeEntry, array[i][0]))
            btn_delete.grid(column=3, row=(i + 3), pady=10)

            # Add "Copy" button to each entry row.
            btn_copy = Button(window, text="Copy",background="gray", command=partial(copyToClipboard, array[i][3]))
            btn_copy.grid(column=4, row=(i + 3), pady=10)

            i += 1
            cursor.execute('SELECT * FROM vault')
            if (len(cursor.fetchall()) <= i):
                break


cursor.execute('SELECT * FROM masterpassword')
if (cursor.fetchall()):
    loginScreen()
else:
    firstTimeScreen()
window.mainloop()