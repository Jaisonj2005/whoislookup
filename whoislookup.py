import tkinter as tk
from tkinter import ttk, messagebox
import whois
import threading

def perform_whois():
    domain = entry_domain.get().strip()
    if not domain:
        messagebox.showerror("Input Error", "Please enter a target domain.")
        return

    # Clean the input in case the user pastes a full URL
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    btn_search.config(state=tk.DISABLED)
    text_output.config(state=tk.NORMAL)
    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, f"[*] Querying WHOIS records for: {clean_domain}\n")
    text_output.insert(tk.END, "-" * 55 + "\n")
    text_output.config(state=tk.DISABLED)
    
    lbl_status.config(text="Querying registries...", fg="#e67e22")
    
    # Offload the network request to a background thread
    threading.Thread(target=lookup_thread, args=(clean_domain,), daemon=True).start()

def lookup_thread(domain):
    try:
        domain_info = whois.whois(domain)
        
        # Extract critical SOC indicators
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date
        registrar = domain_info.registrar
        emails = domain_info.emails
        
        # Format the output for the analyst
        insert_log(f"Registrar       : {registrar}\n", "highlight")
        insert_log(f"Creation Date   : {creation_date}\n", "highlight")
        insert_log(f"Expiration Date : {expiration_date}\n", "highlight")
        insert_log(f"Contact Emails  : {emails}\n\n")
        
        insert_log("--- Raw WHOIS Data ---\n")
        insert_log(str(domain_info))
        
        root.after(0, lambda: lbl_status.config(text="Query Complete", fg="#27ae60"))
        
    except whois.parser.PywhoisError:
        insert_log(f"\n[-] No WHOIS record found for {domain}. It may be unregistered or invalid.", "error")
        root.after(0, lambda: lbl_status.config(text="Not Found", fg="#c0392b"))
    except Exception as e:
        insert_log(f"\n[!] Error during WHOIS lookup: {e}", "error")
        root.after(0, lambda: lbl_status.config(text="Error", fg="#c0392b"))
        
    finally:
        root.after(0, lambda: btn_search.config(state=tk.NORMAL))

def insert_log(message, tag=None):
    text_output.config(state=tk.NORMAL)
    if tag:
        text_output.insert(tk.END, message, tag)
    else:
        text_output.insert(tk.END, message)
    text_output.see(tk.END)
    text_output.config(state=tk.DISABLED)

# --- Tkinter GUI Layout ---
root = tk.Tk()
root.title("SOC Toolkit - Domain WHOIS Intelligence")
root.geometry("650x550")
root.resizable(False, False)

frame = ttk.Frame(root, padding="15")
frame.pack(fill=tk.BOTH, expand=True)

lbl_title = tk.Label(frame, text="OSINT Domain WHOIS Lookup", font=("Helvetica", 13, "bold"))
lbl_title.pack(anchor="w", pady=(0, 5))

lbl_desc = tk.Label(frame, text="Extracts domain registration dates, registrars, and ownership records for threat analysis.", font=("Helvetica", 9), fg="#555")
lbl_desc.pack(anchor="w", pady=(0, 15))

# Input Configuration
config_frame = tk.Frame(frame)
config_frame.pack(fill=tk.X, pady=(0, 15))

tk.Label(config_frame, text="Target Domain:", font=("Helvetica", 9, "bold")).pack(side=tk.LEFT, padx=(0, 10))
entry_domain = ttk.Entry(config_frame, width=40, font=("Consolas", 10))
entry_domain.pack(side=tk.LEFT, padx=(0, 10))
entry_domain.insert(0, "systechgroup.in") 
entry_domain.bind("<Return>", lambda event: perform_whois())

btn_search = tk.Button(config_frame, text="Lookup", command=perform_whois, bg="#2980b9", fg="white", font=("Helvetica", 9, "bold"), width=15)
btn_search.pack(side=tk.LEFT)

# Output Console
text_frame = tk.Frame(frame)
text_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

scrollbar = tk.Scrollbar(text_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

text_output = tk.Text(text_frame, font=("Consolas", 10), bg="#1e1e1e", fg="#ecf0f1", yscrollcommand=scrollbar.set)
text_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
text_output.tag_config("highlight", foreground="#f1c40f", font=("Consolas", 10, "bold"))
text_output.tag_config("error", foreground="#e74c3c")
text_output.config(state=tk.DISABLED)

scrollbar.config(command=text_output.yview)

# Status bar
lbl_status = tk.Label(frame, text="Ready", font=("Consolas", 9), fg="#7f8c8d")
lbl_status.pack(anchor="e")

root.mainloop()