import tkinter as tk
from tkinter import SEL_FIRST, messagebox
from tkinter import ttk
import string
import secrets
import pyperclip # type: ignore

def check_password_strength(password):
    strength = 0
    remarks = ''
    lower_count = upper_count = num_count =  special_count = 0

    for char in list(password):
        if char in string.ascii_lowercase:
            lower_count += 1
        elif char in string.ascii_uppercase:
            upper_count += 1
        elif char in string.digits:
            num_count += 1
        else:
            special_count += 1

    if lower_count >= 1:
        strength += 1
    if upper_count >= 1:
        strength += 1
    if num_count >= 1:
        strength += 1
    if special_count >= 1:
        strength += 1

    if strength == 1:
        remarks = ('That\'s a very bad one.'
                ' Change it.')
    elif strength == 2:
        remarks = ('That\'s a weak password.'
                ' You should consider using a tougher password.')
    elif strength == 3:
        remarks = ('That\'s so close to strong password.'
                'Please try little bit more.') 
    elif strength == 4:
        remarks = ('Now that\'s great'
                ' You can use this password.')

    return f'Your password has:\n{lower_count} lowercase letters\n{upper_count} uppercase letters\n{num_count} digits\n{special_count} special characters\nPassword Score: {strength}/4\nRemarks: {remarks}', strength


def check_password():
    password = password_entry.get()
    result, strength = check_password_strength(password)
    output_text.config(state='normal')
    output_text.delete('1.0', 'end')
    output_text.insert('end', result)
    output_text.config(state='disabled')
    if strength < 1:
        strength_meter["style"] = "orange.Horizontal.TProgressbar"
    elif strength < 2:
        strength_meter["style"] = "green.Horizontal.TProgressbar"
    else:
        strength_meter["style"] = "black.Horizontal.TProgressbar"
    animate_progress_bar(strength_meter, strength * 30, 0)


def generate_password():
    password = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(12))
    password_entry.delete(0, 'end')
    password_entry.insert('end', password)


def copy_password():
    password = password_entry.get()
    if password:
        pyperclip.copy(password)
        messagebox.showinfo("Password Copied", "Password copied to clipboard successfully!")
    else:
        messagebox.showwarning("No Password", "No password to copy!")


def clear_input():
    password_entry.delete(0, 'end')


def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        root.destroy()


def animate_progress_bar(progressbar, target_value, current_value):
    if current_value < target_value:
        progressbar["value"] = current_value
        root.after(10, animate_progress_bar, progressbar, target_value, current_value + 1)


root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("650x400")
root.config(bg="#191919")


frame = tk.Frame(root, bg="#191919")  
frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

label = tk.Label(frame, text="Enter the password:", bg="#191919", fg="white", font=("Arial", 14, "bold"))
label.grid(row=0, column=0, padx=5, pady=5, sticky="e")

password_entry = tk.Entry(frame, show="*", font=("Arial", 12))
password_entry.grid(row=0, column=1, padx=5, pady=5, sticky="we")

check_button = tk.Button(frame, text="Check", command=check_password, border="5", bg="#0000E5", fg="white", font=("arial", 13)) # type: ignore
check_button.grid(row=1, column=0, pady=10, padx=30, sticky="we")

generate_button = tk.Button(frame, text="Generate Password", command=generate_password, border="5", bg="green", fg="white",
                            font=("Arial", 12))

generate_button.place(x=250, y=65)

copy_button = tk.Button(frame, text="Copy Password", command=copy_password, border="5", bg="#0000E5", fg="white",
                        font=("Arial", 12))
copy_button.grid(row=1, column=3, pady=10, padx=5, sticky="we")

clear_button = tk.Button(frame, text="Clear", command=clear_input, border="3", bg="#0000E5", fg="white", font=("Arial", 12))
clear_button.grid(row=0, column=2, pady=10, padx=5, sticky="we")

output_text = tk.Text(frame, height=8, width=60, state='disabled', font=("Arial", 12, "bold"))
output_text.grid(row=2, column=0, columnspan=4, pady=10)

strength_meter = ttk.Progressbar(frame, orient=tk.HORIZONTAL, length=450, mode='determinate', value=0,
                                style="Blue.Horizontal.TProgressbar")
strength_meter.grid(row=3, column=0, columnspan=4, pady=12)

password_entry.bind("<KeyRelease>", lambda event: check_password())

root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()