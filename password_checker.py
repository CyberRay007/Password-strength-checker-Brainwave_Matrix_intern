import re
import customtkinter as ctk
from tkinter import messagebox

weak_passwords = [
    "123456",
    "password",
    "123456789",
    "12345",
    "12345678",
    "qwerty",
    "1234567",
    "111111",
    "123123",
    "abc123",
    "password1",
    "1234",
    "qwerty123",
    "1q2w3e4r",
    "iloveyou",
    "000000",
    "123321",
    "qwertyuiop",
    "letmein",
    "welcome",
    "zulong",
    "zulu",
    "zuly",
    "zuma",
    "zumb",
    "zumi",
    "zune",
    "zuni",
    "zuniga",
    "zura",
    "zuri",
    "zurich",
    "zuzia",
    "zuzu",
    "zwiep",
    "zwin",
    "zwirj",
    "zwitterion",
    "zwzwz",
    "zxas",
    "zxasqw",
    "zxca",
    "zxcasd",
    "zxcmnb",
    "zxcv",
    "zxcvasdf",
    "zxcvbn",
    "zxczxc",
    "zxeri",
    "zxeriy",
    "zxninja",
    "zxzx",
    "zyuw",
    "zzaa",
    "zzaq",
    "zzooum",
    "zztansx",
    "zztop",
    "zzxcvb",
    "zzxx",
    "zzxxvv",
    "zzzaaa",
    "zzzxxx",
    "zzzz",
    "zzzzz",
    "zzzzzz",
    "zzzzzzz",
    "~bruins"
]

def check_password_strength(password, profile_info):
    score = 0
    feedback = []
    weak_flag = False
    if len(password) >= 8:
        score += 2
    else:
        feedback.append("Password should be at least 8 characters.")
    if len(password) >= 12:
        score += 2
    if re.search(r"[A-Z]", password):
        score += 2
    else:
        feedback.append("Add at least one uppercase letter.")
    if re.search(r"[a-z]", password):
        score += 2
    else:
        feedback.append("Add at least one lowercase letter.")
    if re.search(r"[0-9]", password):
        score += 2
    else:
        feedback.append("Add at least one digit.")
    if re.search(r"[@$!%*?&]", password):
        score += 2
    else:
        feedback.append("Add at least one special character (@, $, !, %, *, ?, &).")
    if password.lower() in weak_passwords:
        score -= 3
        feedback.append("This password is too common.")
        weak_flag = True
    password_lower = password.lower()
    for item in profile_info:
        if item and item.lower() in password_lower:
            score -= 3
            feedback.append(f"Password should not contain your personal info ({item}).")
            break
    if score <= 4:
        strength = "Weak"
    elif score <= 8:
        strength = "Medium"
    else:
        strength = "Strong"
    return strength, feedback, score, weak_flag

def run_gui():
    def on_check_password():
        name = entry_name.get().strip()
        email = entry_email.get().strip()
        username = entry_username.get().strip()
        password = entry_password.get()
        if not name or not email or not username or not password:
            messagebox.showwarning("Validation Error", "All fields must be filled in.")
            return
        if "@" not in email or "." not in email:
            messagebox.showwarning("Validation Error", "Enter a valid email address.")
            return
        profile_info = [name, email, username]
        strength, feedback, score, weak_flag = check_password_strength(password, profile_info)
        if weak_flag:
            progress.set(0)
            lbl_strength.configure(text="Strength: Very Weak (Common Password)", text_color="red")
        else:
            progress.set(max(0, min(score * 10, 100)))
            if strength == "Weak":
                lbl_strength.configure(text=f"Strength: {strength}", text_color="red")
            elif strength == "Medium":
                lbl_strength.configure(text=f"Strength: {strength}", text_color="orange")
            else:
                lbl_strength.configure(text=f"Strength: {strength}", text_color="green")
        txt_feedback.delete("0.0", "end")
        if feedback:
            txt_feedback.insert("end", "\n".join(feedback))
        if strength == "Strong" and not weak_flag:
            messagebox.showinfo("Password Checker", " Password accepted! Your password is strong.")

    def toggle_password_visibility():
        if entry_password.cget("show") == "":
            entry_password.configure(show="*")
            btn_toggle.configure(text="Show")
        else:
            entry_password.configure(show="")
            btn_toggle.configure(text="Hide")

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    root = ctk.CTk()
    root.title("Password Strength Checker")
    root.geometry("500x650")

    title = ctk.CTkLabel(root, text="🔑 Password Strength Checker", font=("Arial", 18, "bold"))
    title.pack(pady=10)

    entry_name = ctk.CTkEntry(root, placeholder_text="Enter Name", width=300)
    entry_name.pack(pady=10)

    entry_email = ctk.CTkEntry(root, placeholder_text="Enter Email", width=300)
    entry_email.pack(pady=10)

    entry_username = ctk.CTkEntry(root, placeholder_text="Enter Username", width=300)
    entry_username.pack(pady=10)

    frame = ctk.CTkFrame(root)
    frame.pack(pady=10)
    entry_password = ctk.CTkEntry(frame, placeholder_text="Enter Password", width=220, show="*")
    entry_password.pack(side="left", padx=5)
    btn_toggle = ctk.CTkButton(frame, text="Show", width=60, command=toggle_password_visibility)
    btn_toggle.pack(side="left")

    btn_check = ctk.CTkButton(root, text="Check Strength", command=on_check_password)
    btn_check.pack(pady=15)

    progress = ctk.CTkProgressBar(root, width=300)
    progress.set(0)
    progress.pack(pady=10)

    lbl_strength = ctk.CTkLabel(root, text="Strength: N/A", font=("Arial", 14, "bold"))
    lbl_strength.pack(pady=5)

    lbl_suggestion = ctk.CTkLabel(root, text="Suggestions:", font=("Arial", 12, "bold"))
    lbl_suggestion.pack(pady=5)

    txt_feedback = ctk.CTkTextbox(root, width=400, height=150)
    txt_feedback.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    run_gui()
