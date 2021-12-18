# Modules used
import sqlite3
import hashlib
import tkinter
from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from random import *

# Connect and create Database
conn = sqlite3.connect("pwdvault.db")
c = conn.cursor()

c.execute("""CREATE TABLE IF NOT EXISTS masterpassword(
        password text NOT NULL
        )""")

c.execute("""CREATE TABLE IF NOT EXISTS passwords(
        username text NOT NULL,
        password text NOT NULL,
        application text NOT NULL
        )""")

# Window
root = Tk()

count = 0

# Hash Password
def hash_password(input):
    hash = hashlib.md5(input)
    hash = hash.hexdigest()

    return hash

# Start Window
def start_screen():
    for widget in root.winfo_children():
        widget.destroy()

    root.geometry("250x180")
    root.title("Password Vault")

    # Label and Entry
    pwd_label = Label(root, text="Select a password:")
    pwd_label.pack(pady=10)
    pwd_entry = Entry(root)
    pwd_entry.pack()
    pwd_entry.focus()
    pwd1_label = Label(root, text="Confirm password:")
    pwd1_label.pack()
    pwd1_entry = Entry(root)
    pwd1_entry.pack()
    wrongpwd_label = Label(root)
    wrongpwd_label.pack()

    # Create and Hash password
    def check_password(event):
        conn = sqlite3.connect("pwdvault.db")
        c = conn.cursor()

        hashed_password = hash_password(pwd_entry.get().encode("utf-8"))

        if pwd_entry.get() != pwd1_entry.get():
            wrongpwd_label.config(text="Passwords do not match")
        else:
            c.execute("INSERT INTO masterpassword VALUES(:password)",
                      {
                          "password": hashed_password
                      })

            conn.commit()
            password_manager()


    createpwd_button = Button(root, width=20, text="Save", command=check_password)
    createpwd_button.pack()
    createpwd_button.bind("<Return>", check_password)

# Login Window
def login_screen():
    for widget in root.winfo_children():
        widget.destroy()

    root.geometry("250x130")
    root.title("Password Vault")

    # Labels and Entry
    enter_pwd_label = Label(root, text="Enter password:")
    enter_pwd_label.pack(pady=10)
    enter_pwd_entry = Entry(root, show="*")
    enter_pwd_entry.pack()
    enter_pwd_entry.focus()
    wrong_pwd_label = Label(root)
    wrong_pwd_label.pack()

    # Match password from Database to entry
    def password_check(event):
        conn = sqlite3.connect("pwdvault.db")
        c = conn.cursor()

        c.execute("SELECT * FROM masterpassword WHERE rowid = 1")
        password = c.fetchone()[0]
        entry = hash_password(enter_pwd_entry.get().encode("utf-8"))

        if entry != password:
            wrong_pwd_label.config(text="Wrong password")
        else:
            password_manager()

    submit_button = Button(root, width=20, text="Enter", command=password_check)
    submit_button.pack()
    submit_button.bind("<Return>", password_check)

# Application Window
def password_manager():
    for widget in root.winfo_children():
        widget.destroy()

    root.geometry("700x550")
    root.title("Password Vault")

    # Application name label
    header = Label(root, text="Password Vault", font="Helvetica 30 bold")
    header.pack(anchor=CENTER, pady=(10, 0))

    # Frames
    lf = LabelFrame(root, padx=50, pady=20)
    lf.pack(pady=(10, 30))
    rf = Frame(root)
    rf.pack()
    bf = Frame(root, pady=5)
    bf.pack()

    # TreeView
    tree = tkinter.ttk.Treeview(rf)
    tree.grid(row=0, column=0)

    tree["columns"] = ("ID", "Username", "Password", "App")

    tree.column("#0", width=0, stretch=NO)
    tree.column("ID", width=0, stretch=NO)
    tree.column("Username", width=190)
    tree.column("Password", width=200)
    tree.column("App", width=190)

    tree.heading("#0", text="", anchor=W)
    tree.heading("ID", text="", anchor=W)
    tree.heading("Username", text="Username", anchor=W)
    tree.heading("Password", text="Password", anchor=W)
    tree.heading("App", text="App", anchor=W)

    # Scrollbar
    scrollbar = ttk.Scrollbar(rf, orient="vertical", command=tree.yview)
    tree.configure(yscroll=scrollbar.set)
    scrollbar.grid(row=0, column=1, sticky='ns')

    # Label and Entry
    user_entry = Entry(lf)
    user_label = Label(lf, text="Username:")
    password_entry = Entry(lf)
    password_label = Label(lf, text="Password:")
    application_entry = Entry(lf)
    application_label = Label(lf, text="Application:")

    # Label and Entry placements
    user_label.grid(row=0, column=0)
    user_entry.grid(row=1, column=0, padx=20, pady=10)
    password_label.grid(row=0, column=1)
    password_entry.grid(row=1, column=1, padx=20, pady=10)
    application_label.grid(row=0, column=2)
    application_entry.grid(row=1, column=2, padx=20, pady=10)

    user_entry.focus()

    # Reset application password
    def reset_password():
        conn = sqlite3.connect("pwdvault.db")
        c = conn.cursor()

        c.execute("DELETE from masterpassword WHERE rowid = 1")

        conn.commit()
        conn.close()

        start_screen()

    # File Menu
    menubar = Menu(root)
    root.config(menu=menubar)
    file_menu = Menu(menubar)

    file_menu.add_command(
        label='Reset Password',
        command=reset_password,
    )

    file_menu.add_command(
        label='Close',
        command=root.destroy,
    )

    menubar.add_cascade(
        label='File',
        menu=file_menu,
        underline=0
    )

    # Load Database to TreeView
    def query():
        tree.delete()

        conn = sqlite3.connect("pwdvault.db")
        c = conn.cursor()

        c.execute("SELECT rowid, * FROM passwords")
        records = c.fetchall()

        global count
        count = 1

        for record in records:
            tree.insert(parent="", index="end", iid=count, text="", values=(record[0], record[1], record[2], record[3]))
            count += 1

        conn.commit()
        conn.close()

    # Clear entry boxes
    def clear(e):
        user_entry.delete(0, END)
        password_entry.delete(0, END)
        application_entry.delete(0, END)

    # Select record and grab row ID
    def select_record(e):
        selection = tree.selection()
        item = tree.focus()
        values = tree.item(item, "values")

        global ids_to_delete
        ids_to_delete = []

        user_entry.insert(0, values[1])
        password_entry.insert(0, values[2])
        application_entry.insert(0, values[3])

        for record in selection:
            ids_to_delete.append(tree.item(record, "values")[0])

    # Delete existing entry
    def delete():
        if messagebox.askyesno("showinfo", "Are you sure you want to delete item/s?"):
            x = tree.selection()
            for record in x:
                tree.delete(record)

            conn = sqlite3.connect('pwdvault.db')
            c = conn.cursor()

            global ids_to_delete
            c.executemany("DELETE FROM passwords WHERE oid= ?", [(a,) for a in ids_to_delete])

            conn.commit()
            conn.close()

            clear()

    # Submit new entry
    def submit():
        global count
        tree.insert(parent="", index="end", iid=count, text="",
                    values=(count, user_entry.get(), password_entry.get(), application_entry.get()))
        count += 1

        conn = sqlite3.connect("pwdvault.db")
        c = conn.cursor()

        c.execute("INSERT INTO passwords VALUES (:username, :password, :application)",
                  {
                      "username": user_entry.get(),
                      "password": password_entry.get(),
                      "application": application_entry.get()
                  })

        conn.commit()
        conn.close()

        clear()

    # Generate random password
    def generate():
        password_entry.delete(0, END)
        password = ""

        for numbers in range(7):
            password += chr(choice([randint(48, 57), randint(65, 90), randint(97, 122)]))
        for numbers in range(1):
            password += chr(randint(60, 64))
        for numbers in range(1):
            password += chr(randint(48, 57))
        for numbers in range(1):
            password += chr(randint(65, 90))
        for numbers in range(5):
            password += chr(choice([randint(48, 57), randint(65, 90), randint(97, 122), randint(40, 43)]))

        password_entry.insert(0, password)

    # Update existing entry
    def update():
        global ids_to_delete
        selected = tree.focus()

        tree.item(selected, text="",
                  values=(ids_to_delete[0], user_entry.get(), password_entry.get(), application_entry.get()))

        conn = sqlite3.connect("pwdvault.db")
        c = conn.cursor()

        c.execute("""UPDATE passwords SET
            username = :user,
            password = :pass,
            application = :app
            
            WHERE rowid = :oid""",
                  {
                      "user": user_entry.get(),
                      "pass": password_entry.get(),
                      "app": application_entry.get(),
                      "oid": ids_to_delete[0],
                  })

        c.execute("SELECT rowid, * FROM passwords")

        conn.commit()
        conn.close()

    # Buttons
    submit_button = Button(lf, text="Submit", command=submit, width=8)
    generate_button = Button(lf, text="Generate", width=8, command=generate)
    delete_button = Button(lf, text="Delete", width=8, command=delete)
    update_button = Button(bf, text="Update", width=8, padx=20, command=update)
    submit_button.grid(row=2, column=0)
    generate_button.grid(row=2, column=1)
    delete_button.grid(row=2, column=2)
    update_button.grid(row=1, column=0, padx=15, pady=15)


    # Load Database to TreeView
    query()

    # Binding Keys
    tree.bind("<Double-1>", select_record)
    tree.bind("<Button-1>", clear)

# Automatically open correct window
c.execute("SELECT * FROM masterpassword")
if c.fetchall():
    login_screen()
else:
    start_screen()

conn.commit()
conn.close()

root.mainloop()
