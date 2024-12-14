import tkinter as tk
from tkinter import filedialog, messagebox
import os

class LogLens:
    def __init__(self, root):
        self.root = root
        self.root.title("LogLens - EXE Log Analyzer")
        self.root.geometry("600x400")

        # Header label
        header = tk.Label(root, text="LogLens - EXE Log Analyzer", font=("Arial", 16, "bold"))
        header.pack(pady=10)

        # File selection
        self.file_label = tk.Label(root, text="No file selected", font=("Arial", 12))
        self.file_label.pack(pady=5)

        select_button = tk.Button(root, text="Select Log File", command=self.select_file)
        select_button.pack(pady=5)

        # Analysis section
        analyze_button = tk.Button(root, text="Analyze Log", command=self.analyze_log, state=tk.DISABLED)
        analyze_button.pack(pady=10)
        self.analyze_button = analyze_button

        self.result_text = tk.Text(root, wrap="word", state="disabled", font=("Courier", 10))
        self.result_text.pack(padx=10, pady=10, expand=True, fill="both")

        # Clear Results
        clear_button = tk.Button(root, text="Clear Results", command=self.clear_results, state=tk.DISABLED)
        clear_button.pack(pady=5)
        self.clear_button = clear_button

    def select_file(self):
        file_path = filedialog.askopenfilename(title="Select a log file", filetypes=[("Log files", "*.log"), ("All files", "*.*")])
        if file_path:
            self.file_path = file_path
            self.file_label.config(text=f"Selected File: {os.path.basename(file_path)}")
            self.analyze_button.config(state=tk.NORMAL)

    def analyze_log(self):
        try:
            with open(self.file_path, "r") as file:
                log_content = file.readlines()

            error_count = 0
            warning_count = 0
            info_count = 0
            results = []

            for line in log_content:
                line = line.strip()
                if "ERROR" in line.upper():
                    error_count += 1
                    results.append(f"[ERROR] {line}")
                elif "WARNING" in line.upper():
                    warning_count += 1
                    results.append(f"[WARNING] {line}")
                elif "INFO" in line.upper():
                    info_count += 1
                    results.append(f"[INFO] {line}")

            summary = (f"Analysis Summary:\n"
                       f"Total Errors: {error_count}\n"
                       f"Total Warnings: {warning_count}\n"
                       f"Total Info Messages: {info_count}\n\n")

            self.result_text.config(state="normal")
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, summary + "\n" + "\n".join(results))
            self.result_text.config(state="disabled")
            self.clear_button.config(state=tk.NORMAL)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze the log file: {e}")

    def clear_results(self):
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state="disabled")
        self.clear_button.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = LogLens(root)
    root.mainloop()
