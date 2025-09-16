import re
import tkinter as tk
from tkinter import ttk, messagebox

def load_weak_passwords():
    try:
        with open("common_passwords.txt", "r") as f:
            return [line.strip().lower() for line in f.readlines()]
    except FileNotFoundError:
        return ["password", "123456", "qwerty", "letmein", "abc123"]

weak_passwords = load_weak_passwords()

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

def run_gui(profile_info):
    def on_check_password():
        password = entry_password.get()
        strength, feedback, score, weak_flag = check_password_strength(password, profile_info)
        if weak_flag:
            progress["value"] = 0
            style.configure("red.Horizontal.TProgressbar", foreground="red", background="red")
            progress.config(style="red.Horizontal.TProgressbar")
            lbl_strength.config(text="Strength: Very Weak (Common Password)")
        else:
            progress["value"] = max(0, min(score * 10, 100))
            if strength == "Weak":
                style.configure("red.Horizontal.TProgressbar", foreground="red", background="red")
                progress.config(style="red.Horizontal.TProgressbar")
            elif strength == "Medium":
                style.configure("yellow.Horizontal.TProgressbar", foreground="orange", background="orange")
                progress.config(style="yellow.Horizontal.TProgressbar")
            else:
                style.configure("green.Horizontal.TProgressbar", foreground="green", background="green")
                progress.config(style="green.Horizontal.TProgressbar")
            lbl_strength.config(text=f"Strength: {strength}")
        txt_feedback.delete("1.0", tk.END)
        if feedback:
            txt_feedback.insert(tk.END, "\n".join(feedback))
        if strength == "Strong" and not weak_flag:
            messagebox.showinfo("Password Checker", "✅ Password accepted! Your password is strong.")

    def toggle_password_visibility():
        if entry_password.cget("show") == "":
            entry_password.config(show="*")
            btn_toggle.config(text="Show")
        else:
            entry_password.config(show="")
            btn_toggle.config(text="Hide")

    root = tk.Tk()
    root.title("Password Strength Checker")
    tk.Label(root, text="Enter Password:", font=("Arial", 12)).pack(pady=5)
    frame = tk.Frame(root)
    frame.pack(pady=5)
    entry_password = tk.Entry(frame, show="*", width=30, font=("Arial", 12))
    entry_password.pack(side="left")
    btn_toggle = tk.Button(frame, text="Show", command=toggle_password_visibility)
    btn_toggle.pack(side="left", padx=5)
    btn_check = tk.Button(root, text="Check Strength", command=on_check_password)
    btn_check.pack(pady=10)
    global style
    style = ttk.Style()
    progress = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
    progress.pack(pady=5)
    lbl_strength = tk.Label(root, text="Strength: N/A", font=("Arial", 12, "bold"))
    lbl_strength.pack(pady=5)
    tk.Label(root, text="Suggestions:", font=("Arial", 10, "bold")).pack(pady=5)
    txt_feedback = tk.Text(root, height=6, width=40, wrap="word")
    txt_feedback.pack(pady=5)
    root.mainloop()

if __name__ == "__main__":
    print("Enter your profile details (for uniqueness check):")
    name = input("Enter your name: ")
    email = input("Enter your email: ")
    username = input("Enter your username: ")
    profile_info = [name, email, username]
    print("\nLaunching GUI Password Strength Checker...")
    run_gui(profile_info)
