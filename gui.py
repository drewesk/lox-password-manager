#!/usr/bin/env python3
"""
Lox GUI - Graphical interface for Lox password manager
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import queue
import time
from pathlib import Path
from typing import Optional, Dict, Any, List

from crypto import MultiLayerEncryption, SecureSession
from storage import EncryptedStorage
from security import (
    SecureClipboard,
    PasswordBreachChecker,
    PasswordStrengthAnalyzer,
    RateLimiter,
)


class LoxGUI:
    """Main GUI application for Lox password manager"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Lox Password Manager 🔐")
        self.root.geometry("1000x700")

        # Set theme colors
        self.bg_color = "#1e1e1e"
        self.fg_color = "#ffffff"
        self.accent_color = "#2a9fd6"
        self.warning_color = "#cc0000"
        self.success_color = "#00cc00"

        self.root.configure(bg=self.bg_color)

        # Session and storage
        self.storage: Optional[EncryptedStorage] = None
        self.session: Optional[SecureSession] = None
        self.master_password: Optional[str] = None
        self.storage_path: Optional[Path] = None

        # Clipboard manager
        self.clipboard = SecureClipboard(timeout=45)
        self.rate_limiter = RateLimiter()

        # Breach checker
        self.breach_checker = PasswordBreachChecker()

        # Current vault entries cache
        self.entries: List[Dict[str, Any]] = []
        self.filtered_entries: List[Dict[str, Any]] = []

        # Initialize UI
        self.setup_styles()
        self.show_login_screen()

    def setup_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.theme_use("clam")

        # Configure colors
        style.configure(
            "Title.TLabel",
            background=self.bg_color,
            foreground=self.accent_color,
            font=("Helvetica", 24, "bold"),
        )

        style.configure(
            "Normal.TLabel",
            background=self.bg_color,
            foreground=self.fg_color,
            font=("Helvetica", 10),
        )

        style.configure(
            "Entry.TLabel",
            background=self.bg_color,
            foreground=self.fg_color,
            font=("Helvetica", 11),
        )

        style.configure(
            "Accent.TButton",
            background=self.accent_color,
            foreground=self.fg_color,
            font=("Helvetica", 10, "bold"),
        )

        style.map("Accent.TButton", background=[("active", "#1e7ca6")])

        style.configure(
            "Warning.TButton",
            background=self.warning_color,
            foreground=self.fg_color,
            font=("Helvetica", 10, "bold"),
        )

    def show_login_screen(self):
        """Display login/initialization screen"""
        # Clear window
        for widget in self.root.winfo_children():
            widget.destroy()

        # Title
        title = ttk.Label(
            self.root, text="🔐 Lox Password Manager", style="Title.TLabel"
        )
        title.pack(pady=40)

        # Subtitle
        subtitle = ttk.Label(
            self.root,
            text="Secure password management with military-grade encryption",
            style="Normal.TLabel",
        )
        subtitle.pack(pady=10)

        # Frame for buttons
        button_frame = ttk.Frame(self.root, style="Normal.TLabel")
        button_frame.pack(pady=50)

        # Login button
        login_btn = ttk.Button(
            button_frame,
            text="Unlock Existing Vault",
            style="Accent.TButton",
            command=self.show_unlock_dialog,
        )
        login_btn.pack(pady=10, padx=20, ipadx=20, ipady=10)

        # Initialize button
        init_btn = ttk.Button(
            button_frame,
            text="Create New Vault",
            style="Accent.TButton",
            command=self.show_init_dialog,
        )
        init_btn.pack(pady=10, padx=20, ipadx=20, ipady=10)

        # Storage path info
        default_path = Path.home() / ".lox" / "vault.db"
        path_label = ttk.Label(
            self.root,
            text=f"Default vault location: {default_path}",
            style="Normal.TLabel",
        )
        path_label.pack(pady=20)

        # CLI info
        cli_label = ttk.Label(
            self.root,
            text="You can also use Lox from command line: 'lox --help'",
            style="Normal.TLabel",
        )
        cli_label.pack(pady=10)

    def show_unlock_dialog(self):
        """Show dialog to unlock existing vault"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Unlock Vault")
        dialog.geometry("500x300")
        dialog.configure(bg=self.bg_color)
        dialog.transient(self.root)
        dialog.grab_set()

        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = (
            self.root.winfo_y()
            + (self.root.winfo_height() - dialog.winfo_height()) // 2
        )
        dialog.geometry(f"+{x}+{y}")

        # Title
        title = ttk.Label(dialog, text="Unlock Password Vault", style="Title.TLabel")
        title.pack(pady=20)

        # Storage path
        path_frame = ttk.Frame(dialog, style="Normal.TLabel")
        path_frame.pack(pady=10)

        ttk.Label(path_frame, text="Vault Location:", style="Normal.TLabel").pack(
            side=tk.LEFT
        )
        default_path = Path.home() / ".lox" / "vault.db"
        path_var = tk.StringVar(value=str(default_path))
        path_entry = ttk.Entry(path_frame, textvariable=path_var, width=40)
        path_entry.pack(side=tk.LEFT, padx=10)

        # Browse button
        def browse_vault():
            from tkinter import filedialog

            filepath = filedialog.askopenfilename(
                title="Select Lox vault file",
                filetypes=[("Database files", "*.db"), ("All files", "*.*")],
            )
            if filepath:
                path_var.set(filepath)

        browse_btn = ttk.Button(path_frame, text="Browse...", command=browse_vault)
        browse_btn.pack(side=tk.LEFT)

        # Password
        password_frame = ttk.Frame(dialog, style="Normal.TLabel")
        password_frame.pack(pady=20)

        ttk.Label(password_frame, text="Master Password:", style="Normal.TLabel").pack(
            side=tk.LEFT
        )
        password_var = tk.StringVar()
        password_entry = ttk.Entry(
            password_frame, textvariable=password_var, show="•", width=30
        )
        password_entry.pack(side=tk.LEFT, padx=10)

        # Show password checkbox
        show_var = tk.BooleanVar()

        def toggle_password():
            password_entry.config(show="" if show_var.get() else "•")

        show_check = ttk.Checkbutton(
            password_frame,
            text="Show",
            variable=show_var,
            command=toggle_password,
            style="Normal.TLabel",
        )
        show_check.pack(side=tk.LEFT)

        # Status label
        status_var = tk.StringVar()
        status_label = ttk.Label(dialog, textvariable=status_var, style="Normal.TLabel")
        status_label.pack(pady=10)

        # Unlock button
        def attempt_unlock():
            path = Path(path_var.get())
            password = password_var.get()

            if not path.exists():
                status_var.set("❌ Vault file not found")
                return

            if not password:
                status_var.set("❌ Please enter master password")
                return

            # Try to unlock in background
            status_var.set("🔓 Unlocking vault...")
            dialog.update()

            # Create storage in main thread (SQLite connection lives here)
            storage = EncryptedStorage(str(path))

            # Use threading to avoid UI freeze (password verification only)
            def unlock_thread():
                try:
                    if not storage.verify_master_password(password):
                        status_var.set("❌ Invalid master password")
                        return

                    # Success - store references and show main UI
                    self.storage = storage
                    self.master_password = password
                    self.storage_path = path
                    self.session = SecureSession(password)

                    # Load entries
                    self.load_entries()

                    # Close dialog and show main UI
                    dialog.after(0, lambda: self.show_main_ui(dialog))

                except Exception as e:
                    status_var.set(f"❌ Error: {str(e)}")

            threading.Thread(target=unlock_thread, daemon=True).start()

        unlock_btn = ttk.Button(
            dialog, text="Unlock Vault", style="Accent.TButton", command=attempt_unlock
        )
        unlock_btn.pack(pady=20)

        # Bind Enter key to unlock
        password_entry.bind("<Return>", lambda e: attempt_unlock())

        # Focus password field
        password_entry.focus_set()

    def show_init_dialog(self):
        """Show dialog to initialize new vault"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Create New Vault")
        dialog.geometry("600x500")
        dialog.configure(bg=self.bg_color)
        dialog.transient(self.root)
        dialog.grab_set()

        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = (
            self.root.winfo_y()
            + (self.root.winfo_height() - dialog.winfo_height()) // 2
        )
        dialog.geometry(f"+{x}+{y}")

        # Title
        title = ttk.Label(
            dialog, text="Create New Password Vault", style="Title.TLabel"
        )
        title.pack(pady=20)

        # Storage path
        path_frame = ttk.Frame(dialog, style="Normal.TLabel")
        path_frame.pack(pady=10)

        ttk.Label(path_frame, text="Vault Location:", style="Normal.TLabel").pack(
            side=tk.LEFT
        )
        default_path = Path.home() / ".lox" / "vault.db"
        path_var = tk.StringVar(value=str(default_path))
        path_entry = ttk.Entry(path_frame, textvariable=path_var, width=40)
        path_entry.pack(side=tk.LEFT, padx=10)

        # Browse button
        def browse_vault():
            from tkinter import filedialog

            filepath = filedialog.asksaveasfilename(
                title="Create new vault file",
                defaultextension=".db",
                filetypes=[("Database files", "*.db"), ("All files", "*.*")],
            )
            if filepath:
                path_var.set(filepath)

        browse_btn = ttk.Button(path_frame, text="Browse...", command=browse_vault)
        browse_btn.pack(side=tk.LEFT)

        # Password entry
        password_frame = ttk.Frame(dialog, style="Normal.TLabel")
        password_frame.pack(pady=10)

        ttk.Label(password_frame, text="Master Password:", style="Normal.TLabel").pack()
        password_var = tk.StringVar()
        password_entry = ttk.Entry(
            password_frame, textvariable=password_var, show="•", width=30
        )
        password_entry.pack(pady=5)

        # Confirm password
        confirm_frame = ttk.Frame(dialog, style="Normal.TLabel")
        confirm_frame.pack(pady=10)

        ttk.Label(confirm_frame, text="Confirm Password:", style="Normal.TLabel").pack()
        confirm_var = tk.StringVar()
        confirm_entry = ttk.Entry(
            confirm_frame, textvariable=confirm_var, show="•", width=30
        )
        confirm_entry.pack(pady=5)

        # Show password checkbox
        show_var = tk.BooleanVar()

        def toggle_passwords():
            show = "" if show_var.get() else "•"
            password_entry.config(show=show)
            confirm_entry.config(show=show)

        show_check = ttk.Checkbutton(
            dialog,
            text="Show passwords",
            variable=show_var,
            command=toggle_passwords,
            style="Normal.TLabel",
        )
        show_check.pack(pady=5)

        # Password strength indicator
        strength_var = tk.StringVar(value="Password strength: -")
        strength_label = ttk.Label(
            dialog, textvariable=strength_var, style="Normal.TLabel"
        )
        strength_label.pack(pady=5)

        # Update strength on typing
        def update_strength(*args):
            password = password_var.get()
            if password:
                analyzer = PasswordStrengthAnalyzer()
                result = analyzer.analyze_strength(password)
                strength_var.set(
                    f"Password strength: {result['strength']} ({result['score']}%)"
                )

                # Color code
                if result["score"] < 30:
                    strength_label.configure(foreground=self.warning_color)
                elif result["score"] < 60:
                    strength_label.configure(foreground="orange")
                elif result["score"] < 80:
                    strength_label.configure(foreground="light blue")
                else:
                    strength_label.configure(foreground=self.success_color)
            else:
                strength_var.set("Password strength: -")
                strength_label.configure(foreground=self.fg_color)

        password_var.trace("w", update_strength)

        # Warning label
        warning_label = ttk.Label(
            dialog,
            text="⚠️  Your master password cannot be recovered if lost!",
            style="Normal.TLabel",
        )
        warning_label.pack(pady=10)

        # Status label
        status_var = tk.StringVar()
        status_label = ttk.Label(dialog, textvariable=status_var, style="Normal.TLabel")
        status_label.pack(pady=10)

        # Create button
        def create_vault():
            path = Path(path_var.get())
            password = password_var.get()
            confirm = confirm_var.get()

            if path.exists():
                response = messagebox.askyesno(
                    "Vault exists",
                    f"A vault already exists at {path}. Overwrite? (THIS WILL DELETE ALL DATA)",
                )
                if not response:
                    return

            if password != confirm:
                status_var.set("❌ Passwords do not match")
                return

            if len(password) < 8:
                status_var.set("❌ Password must be at least 8 characters")
                return

            # Check password strength
            analyzer = PasswordStrengthAnalyzer()
            result = analyzer.analyze_strength(password)
            if result["score"] < 30:
                response = messagebox.askyesno(
                    "Weak Password",
                    "Your password is weak. Are you sure you want to continue?",
                )
                if not response:
                    return

            # Create vault in background
            status_var.set("🔨 Creating encrypted vault...")
            dialog.update()

            # Create storage in main thread (SQLite connection lives here)
            storage = EncryptedStorage(str(path))

            def create_thread():
                try:
                    storage.initialize(password)

                    # Success
                    self.storage = storage
                    self.master_password = password
                    self.storage_path = path
                    self.session = SecureSession(password)

                    dialog.after(0, lambda: self.show_main_ui(dialog))

                except Exception as e:
                    status_var.set(f"❌ Error: {str(e)}")

            threading.Thread(target=create_thread, daemon=True).start()

        create_btn = ttk.Button(
            dialog, text="Create Vault", style="Accent.TButton", command=create_vault
        )
        create_btn.pack(pady=20)

        # Bind Enter key to create
        password_entry.bind("<Return>", lambda e: create_vault())
        confirm_entry.bind("<Return>", lambda e: create_vault())

        # Focus password field
        password_entry.focus_set()

    def load_entries(self):
        """Load all entries from vault"""
        if not self.storage or not self.master_password:
            return

        try:
            self.entries = self.storage.list_passwords(self.master_password)
            self.filtered_entries = self.entries.copy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load entries: {e}")

    def show_main_ui(self, previous_dialog=None):
        """Show main application UI"""
        if previous_dialog:
            previous_dialog.destroy()

        # Clear window
        for widget in self.root.winfo_children():
            widget.destroy()

        # Create main layout
        main_frame = ttk.Frame(self.root, style="Normal.TLabel")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Header
        header_frame = ttk.Frame(main_frame, style="Normal.TLabel")
        header_frame.pack(fill=tk.X, pady=(0, 20))

        title = ttk.Label(
            header_frame, text="🔐 Lox Password Vault", style="Title.TLabel"
        )
        title.pack(side=tk.LEFT)

        # Session info
        vault_name = self.storage_path.name if self.storage_path else "Unknown"
        info_text = f"Vault: {vault_name} | Entries: {len(self.entries)}"
        info_label = ttk.Label(header_frame, text=info_text, style="Normal.TLabel")
        info_label.pack(side=tk.RIGHT)

        # Search bar
        search_frame = ttk.Frame(main_frame, style="Normal.TLabel")
        search_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(search_frame, text="Search:", style="Normal.TLabel").pack(
            side=tk.LEFT
        )
        search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=search_var, width=40)
        search_entry.pack(side=tk.LEFT, padx=10)

        # Clear search button
        def clear_search():
            search_var.set("")
            self.filtered_entries = self.entries.copy()
            self.update_entries_list()

        clear_btn = ttk.Button(search_frame, text="Clear", command=clear_search)
        clear_btn.pack(side=tk.LEFT)

        # Search on typing
        def on_search(*args):
            query = search_var.get().lower()
            if not query:
                self.filtered_entries = self.entries.copy()
            else:
                self.filtered_entries = [
                    entry
                    for entry in self.entries
                    if query in entry["name"].lower()
                    or (entry.get("username") and query in entry["username"].lower())
                    or (entry.get("url") and query in entry["url"].lower())
                    or any(query in tag.lower() for tag in entry.get("tags", []))
                ]
            self.update_entries_list()

        search_var.trace("w", on_search)

        # Main content area
        content_frame = ttk.Frame(main_frame, style="Normal.TLabel")
        content_frame.pack(fill=tk.BOTH, expand=True)

        # Left panel - entries list
        left_frame = ttk.Frame(content_frame, style="Normal.TLabel")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        # List header
        list_header = ttk.Frame(left_frame, style="Normal.TLabel")
        list_header.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(list_header, text="Stored Passwords", style="Entry.TLabel").pack(
            side=tk.LEFT
        )

        # Add new button
        add_btn = ttk.Button(
            list_header,
            text="+ Add New",
            style="Accent.TButton",
            command=self.show_add_dialog,
        )
        add_btn.pack(side=tk.RIGHT)

        # Entries listbox
        list_frame = ttk.Frame(left_frame, style="Normal.TLabel")
        list_frame.pack(fill=tk.BOTH, expand=True)

        # Create treeview for entries
        columns = ("name", "username", "tags")
        self.tree = ttk.Treeview(
            list_frame, columns=columns, show="headings", height=20
        )

        # Define headings
        self.tree.heading("name", text="Name")
        self.tree.heading("username", text="Username")
        self.tree.heading("tags", text="Tags")

        # Define column widths
        self.tree.column("name", width=200)
        self.tree.column("username", width=150)
        self.tree.column("tags", width=100)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            list_frame, orient=tk.VERTICAL, command=self.tree.yview
        )
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind selection
        self.tree.bind("<<TreeviewSelect>>", self.on_entry_select)

        # Right panel - entry details
        right_frame = ttk.Frame(content_frame, style="Normal.TLabel", width=400)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False)
        right_frame.pack_propagate(False)  # Don't let children determine frame size

        # Details header
        details_header = ttk.Frame(right_frame, style="Normal.TLabel")
        details_header.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(details_header, text="Password Details", style="Entry.TLabel").pack(
            side=tk.LEFT
        )

        # Details content
        details_frame = ttk.Frame(right_frame, style="Normal.TLabel")
        details_frame.pack(fill=tk.BOTH, expand=True)

        # Current entry info
        self.details_vars = {
            "name": tk.StringVar(),
            "username": tk.StringVar(),
            "url": tk.StringVar(),
            "password": tk.StringVar(),
            "notes": tk.StringVar(),
            "tags": tk.StringVar(),
        }

        # Create labels
        for i, (field, var) in enumerate(self.details_vars.items()):
            frame = ttk.Frame(details_frame, style="Normal.TLabel")
            frame.pack(fill=tk.X, pady=5)

            label = ttk.Label(
                frame, text=field.capitalize() + ":", style="Normal.TLabel"
            )
            label.pack(side=tk.LEFT)

            if field == "password":
                # Password with show/hide
                entry_frame = ttk.Frame(frame, style="Normal.TLabel")
                entry_frame.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

                entry = ttk.Entry(
                    entry_frame, textvariable=var, show="•", state="readonly"
                )
                entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

                # Show/hide button
                show_var = tk.BooleanVar()

                def toggle_password(v=show_var, e=entry):
                    e.config(show="" if v.get() else "•")

                show_btn = ttk.Checkbutton(
                    entry_frame,
                    text="Show",
                    variable=show_var,
                    command=toggle_password,
                    style="Normal.TLabel",
                )
                show_btn.pack(side=tk.RIGHT)

                # Copy button
                copy_btn = ttk.Button(
                    entry_frame,
                    text="Copy",
                    command=lambda v=var: self.copy_to_clipboard(v.get()),
                )
                copy_btn.pack(side=tk.RIGHT, padx=5)

            elif field == "notes":
                # Text widget for notes
                text_frame = ttk.Frame(frame, style="Normal.TLabel")
                text_frame.pack(side=tk.LEFT, padx=10, fill=tk.BOTH, expand=True)

                text_widget = tk.Text(
                    text_frame,
                    height=4,
                    width=30,
                    bg=self.bg_color,
                    fg=self.fg_color,
                    insertbackground=self.fg_color,
                )
                text_widget.pack(fill=tk.BOTH, expand=True)

                # Sync with variable
                def update_text(*args, tw=text_widget, v=var):
                    tw.delete(1.0, tk.END)
                    tw.insert(1.0, v.get())

                var.trace("w", update_text)

                # Update variable on text change
                def text_changed(event=None, tw=text_widget, v=var):
                    v.set(tw.get(1.0, tk.END).strip())

                text_widget.bind("<KeyRelease>", text_changed)
                self.notes_text = text_widget

            else:
                entry = ttk.Entry(frame, textvariable=var, state="readonly")
                entry.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        # Action buttons frame
        action_frame = ttk.Frame(details_frame, style="Normal.TLabel")
        action_frame.pack(fill=tk.X, pady=20)

        # Edit button
        edit_btn = ttk.Button(
            action_frame,
            text="Edit Entry",
            style="Accent.TButton",
            command=self.edit_current_entry,
        )
        edit_btn.pack(side=tk.LEFT, padx=5)

        # Delete button
        delete_btn = ttk.Button(
            action_frame,
            text="Delete Entry",
            style="Warning.TButton",
            command=self.delete_current_entry,
        )
        delete_btn.pack(side=tk.LEFT, padx=5)

        # Generate button
        generate_btn = ttk.Button(
            action_frame,
            text="Generate New",
            style="Accent.TButton",
            command=self.show_generate_dialog,
        )
        generate_btn.pack(side=tk.RIGHT, padx=5)

        # Bottom toolbar
        toolbar_frame = ttk.Frame(main_frame, style="Normal.TLabel")
        toolbar_frame.pack(fill=tk.X, pady=(20, 0))

        # Export button
        export_btn = ttk.Button(
            toolbar_frame,
            text="Export Vault",
            style="Accent.TButton",
            command=self.show_export_dialog,
        )
        export_btn.pack(side=tk.LEFT, padx=5)

        # Import button
        import_btn = ttk.Button(
            toolbar_frame,
            text="Import Backup",
            style="Accent.TButton",
            command=self.show_import_dialog,
        )
        import_btn.pack(side=tk.LEFT, padx=5)

        # Lock button
        lock_btn = ttk.Button(
            toolbar_frame,
            text="🔒 Lock Vault",
            style="Warning.TButton",
            command=self.lock_vault,
        )
        lock_btn.pack(side=tk.RIGHT, padx=5)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(
            main_frame, textvariable=self.status_var, style="Normal.TLabel"
        )
        status_bar.pack(fill=tk.X, pady=(10, 0))

        # Initial update
        self.update_entries_list()

    def update_entries_list(self):
        """Update the entries treeview"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Add filtered entries
        for entry in self.filtered_entries:
            tags_str = ", ".join(entry.get("tags", []))
            self.tree.insert(
                "", tk.END, values=(entry["name"], entry.get("username", ""), tags_str)
            )

    def on_entry_select(self, event):
        """Handle entry selection from list"""
        selection = self.tree.selection()
        if not selection:
            return

        # Get selected entry name
        item = self.tree.item(selection[0])
        entry_name = item["values"][0]

        # Find full entry
        for entry in self.filtered_entries:
            if entry["name"] == entry_name:
                self.show_entry_details(entry)
                break

    def show_entry_details(self, entry):
        """Display entry details in right panel"""
        # Get full entry with password
        if not self.storage or not self.master_password:
            return

        try:
            full_entry = self.storage.get_password(self.master_password, entry["name"])
            if not full_entry:
                return

            # Update variables
            self.details_vars["name"].set(full_entry["name"])
            self.details_vars["username"].set(full_entry.get("username", ""))
            self.details_vars["url"].set(full_entry.get("url", ""))
            self.details_vars["password"].set(full_entry.get("password", ""))
            self.details_vars["notes"].set(full_entry.get("notes", ""))

            tags = full_entry.get("tags", [])
            self.details_vars["tags"].set(", ".join(tags))

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load entry: {e}")

    def copy_to_clipboard(self, text):
        """Copy text to clipboard with secure timeout"""
        if not text:
            return

        self.clipboard.copy(text)
        self.status_var.set("📋 Copied to clipboard (clears in 45 seconds)")

    def generate_password(self, length: int = 32, include_symbols: bool = True) -> str:
        """Generate a secure random password"""
        crypto = MultiLayerEncryption()
        return crypto.generate_secure_password(
            length=length, include_symbols=include_symbols
        )

    def show_add_dialog(self):
        """Show dialog to add new password"""
        if not self.master_password or not self.storage:
            messagebox.showerror("Error", "Not authenticated")
            return
        assert self.master_password is not None
        assert self.storage is not None
        storage = self.storage
        master_password = self.master_password

        dialog = tk.Toplevel(self.root)
        dialog.title("Add New Password")
        dialog.geometry("600x700")
        dialog.configure(bg=self.bg_color)
        dialog.transient(self.root)
        dialog.grab_set()

        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = (
            self.root.winfo_y()
            + (self.root.winfo_height() - dialog.winfo_height()) // 2
        )
        dialog.geometry(f"+{x}+{y}")

        # Title
        title = ttk.Label(dialog, text="Add New Password Entry", style="Title.TLabel")
        title.pack(pady=20)

        # Form fields
        fields_frame = ttk.Frame(dialog, style="Normal.TLabel")
        fields_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Field definitions
        fields = [
            ("name", "Name*", ""),
            ("username", "Username/Email", ""),
            ("url", "URL", ""),
            ("password", "Password*", ""),
            ("notes", "Notes", ""),
            ("tags", "Tags (comma-separated)", ""),
        ]

        entries = {}

        for i, (field, label, default) in enumerate(fields):
            frame = ttk.Frame(fields_frame, style="Normal.TLabel")
            frame.pack(fill=tk.X, pady=8)

            ttk.Label(frame, text=label, style="Normal.TLabel").pack(
                side=tk.LEFT, anchor="w", width=150
            )

            if field == "password":
                # Password with show/hide and generate
                entry_frame = ttk.Frame(frame, style="Normal.TLabel")
                entry_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

                var = tk.StringVar()
                entry = ttk.Entry(entry_frame, textvariable=var, show="•", width=30)
                entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

                # Show/hide button
                show_var = tk.BooleanVar()
                show_btn = ttk.Checkbutton(
                    entry_frame,
                    text="Show",
                    variable=show_var,
                    command=lambda v=show_var, e=entry: e.config(
                        show="" if v.get() else "•"
                    ),
                    style="Normal.TLabel",
                )
                show_btn.pack(side=tk.LEFT, padx=5)

                # Generate button
                gen_btn = ttk.Button(
                    entry_frame,
                    text="Generate",
                    command=lambda v=var: v.set(self.generate_password()),
                )
                gen_btn.pack(side=tk.LEFT, padx=5)

                # Strength indicator
                strength_var = tk.StringVar(value="")
                strength_label = ttk.Label(
                    entry_frame, textvariable=strength_var, style="Normal.TLabel"
                )
                strength_label.pack(side=tk.LEFT, padx=5)

                def update_strength(v=var, sv=strength_var, sl=strength_label, *args):
                    password = v.get()
                    if password:
                        analyzer = PasswordStrengthAnalyzer()
                        result = analyzer.analyze_strength(password)
                        sv.set(f"{result['strength']} ({result['score']}%)")
                        if result["score"] < 30:
                            sl.configure(foreground=self.warning_color)
                        elif result["score"] < 60:
                            sl.configure(foreground="orange")
                        elif result["score"] < 80:
                            sl.configure(foreground="light blue")
                        else:
                            sl.configure(foreground=self.success_color)
                    else:
                        sv.set("")

                var.trace("w", update_strength)

                entries[field] = var

            elif field == "notes":
                # Text widget for notes
                text_frame = ttk.Frame(frame, style="Normal.TLabel")
                text_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

                text_widget = tk.Text(
                    text_frame,
                    height=4,
                    width=30,
                    bg=self.bg_color,
                    fg=self.fg_color,
                    insertbackground=self.fg_color,
                )
                text_widget.pack(fill=tk.BOTH, expand=True)

                # Store text widget reference
                entries[field] = text_widget

            else:
                var = tk.StringVar(value=default)
                entry = ttk.Entry(frame, textvariable=var, width=30)
                entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
                entries[field] = var

        # Breach check result
        breach_var = tk.StringVar(value="")
        breach_label = ttk.Label(dialog, textvariable=breach_var, style="Normal.TLabel")
        breach_label.pack(pady=10)

        # Check breach button
        def check_breach():
            password = entries["password"].get()
            if not password:
                breach_var.set("❌ No password to check")
                return

            breach_var.set("🔍 Checking breach database...")
            dialog.update()

            def check_thread():
                count = self.breach_checker.check_breach(password)
                if count is None:
                    breach_var.set("⚠️  Could not check breaches (network error)")
                elif count == 0:
                    breach_var.set("🛡️  Password not found in known breaches")
                else:
                    breach_var.set(f"🚨 Password found in {count:,} breaches!")

            threading.Thread(target=check_thread, daemon=True).start()

        check_btn = ttk.Button(
            dialog, text="Check Password Breaches", command=check_breach
        )
        check_btn.pack(pady=5)

        # Status label
        status_var = tk.StringVar(value="")
        status_label = ttk.Label(dialog, textvariable=status_var, style="Normal.TLabel")
        status_label.pack(pady=10)

        # Save button
        def save_entry():
            # Validate required fields
            name = entries["name"].get().strip()
            password = entries["password"].get()

            if not name:
                status_var.set("❌ Name is required")
                return

            if not password:
                status_var.set("❌ Password is required")
                return

            # Get other fields
            username = entries["username"].get().strip()
            url = entries["url"].get().strip()
            notes = (
                entries["notes"].get(1.0, tk.END).strip() if "notes" in entries else ""
            )
            tags_str = entries["tags"].get().strip()
            tags = [tag.strip() for tag in tags_str.split(",")] if tags_str else []

            # Check if entry already exists
            existing = storage.get_password(master_password, name)
            if existing:
                response = messagebox.askyesno(
                    "Entry Exists", f"Password '{name}' already exists. Overwrite?"
                )
                if not response:
                    return

            # Save entry
            status_var.set("💾 Saving password...")
            dialog.update()

            def save_thread():
                try:
                    storage.insert_password(
                        master_password=master_password,
                        name=name,
                        password=password,
                        username=username if username else None,
                        url=url if url else None,
                        notes=notes if notes else None,
                        tags=tags if tags else None,
                    )

                    # Refresh list
                    self.load_entries()
                    self.filtered_entries = self.entries.copy()
                    self.update_entries_list()

                    # Close dialog
                    dialog.after(0, dialog.destroy)
                    self.status_var.set(f"✅ Added '{name}'")

                except Exception as e:
                    status_var.set(f"❌ Error: {str(e)}")

            threading.Thread(target=save_thread, daemon=True).start()

        save_btn = ttk.Button(
            dialog, text="Save Password", style="Accent.TButton", command=save_entry
        )
        save_btn.pack(pady=20)

        # Bind Enter key to save
        dialog.bind("<Return>", lambda e: save_entry())

        # Focus name field (name entry widget not stored, skip focus)

    def show_generate_dialog(self):
        """Show dialog to generate new password"""
        if not self.master_password or not self.storage:
            messagebox.showerror("Error", "Not authenticated")
            return
        assert self.master_password is not None
        assert self.storage is not None
        storage = self.storage
        master_password = self.master_password

        dialog = tk.Toplevel(self.root)
        dialog.title("Generate New Password")
        dialog.geometry("500x500")
        dialog.configure(bg=self.bg_color)
        dialog.transient(self.root)
        dialog.grab_set()

        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = (
            self.root.winfo_y()
            + (self.root.winfo_height() - dialog.winfo_height()) // 2
        )
        dialog.geometry(f"+{x}+{y}")

        # Title
        title = ttk.Label(dialog, text="Generate Secure Password", style="Title.TLabel")
        title.pack(pady=20)

        # Name field
        name_frame = ttk.Frame(dialog, style="Normal.TLabel")
        name_frame.pack(pady=10)

        ttk.Label(name_frame, text="Entry Name*:", style="Normal.TLabel").pack(
            side=tk.LEFT
        )
        name_var = tk.StringVar()
        name_entry = ttk.Entry(name_frame, textvariable=name_var, width=30)
        name_entry.pack(side=tk.LEFT, padx=10)

        # Length
        length_frame = ttk.Frame(dialog, style="Normal.TLabel")
        length_frame.pack(pady=10)

        ttk.Label(length_frame, text="Password Length:", style="Normal.TLabel").pack(
            side=tk.LEFT
        )
        length_var = tk.IntVar(value=32)
        length_spin = ttk.Spinbox(
            length_frame, from_=8, to=128, textvariable=length_var, width=10
        )
        length_spin.pack(side=tk.LEFT, padx=10)

        # Symbols checkbox
        symbols_var = tk.BooleanVar(value=True)
        symbols_check = ttk.Checkbutton(
            dialog,
            text="Include Symbols (!@#$% etc)",
            variable=symbols_var,
            style="Normal.TLabel",
        )
        symbols_check.pack(pady=10)

        # Username and URL
        username_frame = ttk.Frame(dialog, style="Normal.TLabel")
        username_frame.pack(pady=10)

        ttk.Label(
            username_frame, text="Username (optional):", style="Normal.TLabel"
        ).pack(side=tk.LEFT)
        username_var = tk.StringVar()
        username_entry = ttk.Entry(username_frame, textvariable=username_var, width=30)
        username_entry.pack(side=tk.LEFT, padx=10)

        url_frame = ttk.Frame(dialog, style="Normal.TLabel")
        url_frame.pack(pady=10)

        ttk.Label(url_frame, text="URL (optional):", style="Normal.TLabel").pack(
            side=tk.LEFT
        )
        url_var = tk.StringVar()
        url_entry = ttk.Entry(url_frame, textvariable=url_var, width=30)
        url_entry.pack(side=tk.LEFT, padx=10)

        # Tags
        tags_frame = ttk.Frame(dialog, style="Normal.TLabel")
        tags_frame.pack(pady=10)

        ttk.Label(
            tags_frame, text="Tags (comma-separated):", style="Normal.TLabel"
        ).pack(side=tk.LEFT)
        tags_var = tk.StringVar()
        tags_entry = ttk.Entry(tags_frame, textvariable=tags_var, width=30)
        tags_entry.pack(side=tk.LEFT, padx=10)

        # Generated password display
        password_frame = ttk.Frame(dialog, style="Normal.TLabel")
        password_frame.pack(pady=20)

        ttk.Label(
            password_frame, text="Generated Password:", style="Normal.TLabel"
        ).pack()
        password_var = tk.StringVar()
        password_entry = ttk.Entry(
            password_frame,
            textvariable=password_var,
            font=("Courier", 12),
            state="readonly",
            width=40,
        )
        password_entry.pack(pady=10)

        # Copy button
        copy_btn = ttk.Button(
            password_frame,
            text="Copy",
            command=lambda: self.copy_to_clipboard(password_var.get()),
        )
        copy_btn.pack()

        # Generate button
        def generate_password():
            length = length_var.get()
            include_symbols = symbols_var.get()
            password = self.generate_password(length, include_symbols)
            password_var.set(password)

        gen_btn = ttk.Button(
            dialog,
            text="Generate Password",
            style="Accent.TButton",
            command=generate_password,
        )
        gen_btn.pack(pady=10)

        # Status label
        status_var = tk.StringVar(value="")
        status_label = ttk.Label(dialog, textvariable=status_var, style="Normal.TLabel")
        status_label.pack(pady=10)

        # Save button
        def save_generated():
            name = name_var.get().strip()
            password = password_var.get()

            if not name:
                status_var.set("❌ Entry name is required")
                return

            if not password:
                status_var.set("❌ Generate a password first")
                return

            # Check if entry exists
            existing = storage.get_password(master_password, name)
            if existing:
                response = messagebox.askyesno(
                    "Entry Exists", f"Password '{name}' already exists. Overwrite?"
                )
                if not response:
                    return

            # Save entry
            status_var.set("💾 Saving password...")
            dialog.update()

            def save_thread():
                try:
                    username = username_var.get().strip()
                    url = url_var.get().strip()
                    tags_str = tags_var.get().strip()
                    tags = (
                        [tag.strip() for tag in tags_str.split(",")] if tags_str else []
                    )

                    storage.insert_password(
                        master_password=master_password,
                        name=name,
                        password=password,
                        username=username if username else None,
                        url=url if url else None,
                        tags=tags if tags else None,
                    )

                    # Refresh list
                    self.load_entries()
                    self.filtered_entries = self.entries.copy()
                    self.update_entries_list()

                    # Close dialog
                    dialog.after(0, dialog.destroy)
                    self.status_var.set(f"✅ Generated password for '{name}'")

                except Exception as e:
                    status_var.set(f"❌ Error: {str(e)}")

            threading.Thread(target=save_thread, daemon=True).start()

        save_btn = ttk.Button(
            dialog, text="Save to Vault", style="Accent.TButton", command=save_generated
        )
        save_btn.pack(pady=20)

        # Generate on Enter in name field
        name_entry.bind("<Return>", lambda e: generate_password())

        # Focus name field
        name_entry.focus_set()

    def edit_current_entry(self):
        """Edit currently selected entry"""
        if not self.master_password or not self.storage:
            messagebox.showerror("Error", "Not authenticated")
            return

        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "No entry selected")
            return

        item = self.tree.item(selection[0])
        entry_name = item["values"][0]

        try:
            entry = self.storage.get_password(self.master_password, entry_name)
            if not entry:
                messagebox.showerror("Error", f"Entry '{entry_name}' not found")
                return

            self.show_edit_dialog(entry)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load entry: {e}")

    def show_edit_dialog(self, entry):
        """Show dialog to edit existing password entry"""
        if not self.master_password or not self.storage:
            messagebox.showerror("Error", "Not authenticated")
            return
        assert self.master_password is not None
        assert self.storage is not None
        storage = self.storage
        master_password = self.master_password
        original_name = entry["name"]

        dialog = tk.Toplevel(self.root)
        dialog.title("Edit Password Entry")
        dialog.geometry("600x700")
        dialog.configure(bg=self.bg_color)
        dialog.transient(self.root)
        dialog.grab_set()

        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = (
            self.root.winfo_y()
            + (self.root.winfo_height() - dialog.winfo_height()) // 2
        )
        dialog.geometry(f"+{x}+{y}")

        # Title
        title = ttk.Label(dialog, text="Edit Password Entry", style="Title.TLabel")
        title.pack(pady=20)

        # Form fields
        fields_frame = ttk.Frame(dialog, style="Normal.TLabel")
        fields_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Field definitions with existing values
        fields = [
            ("name", "Name*", entry["name"]),
            ("username", "Username/Email", entry.get("username", "")),
            ("url", "URL", entry.get("url", "")),
            ("password", "Password*", entry.get("password", "")),
            ("notes", "Notes", entry.get("notes", "")),
            ("tags", "Tags (comma-separated)", ", ".join(entry.get("tags", []))),
        ]

        entries = {}

        for i, (field, label, default) in enumerate(fields):
            frame = ttk.Frame(fields_frame, style="Normal.TLabel")
            frame.pack(fill=tk.X, pady=8)

            ttk.Label(frame, text=label, style="Normal.TLabel").pack(
                side=tk.LEFT, anchor="w", width=150
            )

            if field == "password":
                # Password with show/hide and generate
                entry_frame = ttk.Frame(frame, style="Normal.TLabel")
                entry_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

                var = tk.StringVar(value=default)
                entry_widget = ttk.Entry(
                    entry_frame, textvariable=var, show="•", width=30
                )
                entry_widget.pack(side=tk.LEFT, fill=tk.X, expand=True)

                # Show/hide button
                show_var = tk.BooleanVar()
                show_btn = ttk.Checkbutton(
                    entry_frame,
                    text="Show",
                    variable=show_var,
                    command=lambda v=show_var, e=entry_widget: e.config(
                        show="" if v.get() else "•"
                    ),
                    style="Normal.TLabel",
                )
                show_btn.pack(side=tk.LEFT, padx=5)

                # Generate button
                gen_btn = ttk.Button(
                    entry_frame,
                    text="Generate",
                    command=lambda v=var: v.set(self.generate_password()),
                )
                gen_btn.pack(side=tk.LEFT, padx=5)

                # Strength indicator
                strength_var = tk.StringVar(value="")
                strength_label = ttk.Label(
                    entry_frame, textvariable=strength_var, style="Normal.TLabel"
                )
                strength_label.pack(side=tk.LEFT, padx=5)

                def update_strength(v=var, sv=strength_var, sl=strength_label, *args):
                    password = v.get()
                    if password:
                        analyzer = PasswordStrengthAnalyzer()
                        result = analyzer.analyze_strength(password)
                        sv.set(f"{result['strength']} ({result['score']}%)")
                        if result["score"] < 30:
                            sl.configure(foreground=self.warning_color)
                        elif result["score"] < 60:
                            sl.configure(foreground="orange")
                        elif result["score"] < 80:
                            sl.configure(foreground="light blue")
                        else:
                            sl.configure(foreground=self.success_color)
                    else:
                        sv.set("")

                var.trace("w", update_strength)
                # Trigger initial strength update
                update_strength()

                entries[field] = var

            elif field == "notes":
                # Text widget for notes
                text_frame = ttk.Frame(frame, style="Normal.TLabel")
                text_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

                text_widget = tk.Text(
                    text_frame,
                    height=4,
                    width=30,
                    bg=self.bg_color,
                    fg=self.fg_color,
                    insertbackground=self.fg_color,
                )
                text_widget.pack(fill=tk.BOTH, expand=True)
                text_widget.insert(1.0, default)

                # Store text widget reference
                entries[field] = text_widget

            else:
                var = tk.StringVar(value=default)
                entry_widget = ttk.Entry(frame, textvariable=var, width=30)
                entry_widget.pack(side=tk.LEFT, fill=tk.X, expand=True)
                entries[field] = var
                # Make name field read-only
                if field == "name":
                    entry_widget.configure(state="readonly")

        # Breach check result
        breach_var = tk.StringVar(value="")
        breach_label = ttk.Label(dialog, textvariable=breach_var, style="Normal.TLabel")
        breach_label.pack(pady=10)

        # Check breach button
        def check_breach():
            password = entries["password"].get()
            if not password:
                breach_var.set("❌ No password to check")
                return

            breach_var.set("🔍 Checking breach database...")
            dialog.update()

            def check_thread():
                count = self.breach_checker.check_breach(password)
                if count is None:
                    breach_var.set("⚠️  Could not check breaches (network error)")
                elif count == 0:
                    breach_var.set("🛡️  Password not found in known breaches")
                else:
                    breach_var.set(f"🚨 Password found in {count:,} breaches!")

            threading.Thread(target=check_thread, daemon=True).start()

        check_btn = ttk.Button(
            dialog, text="Check Password Breaches", command=check_breach
        )
        check_btn.pack(pady=5)

        # Status label
        status_var = tk.StringVar(value="")
        status_label = ttk.Label(dialog, textvariable=status_var, style="Normal.TLabel")
        status_label.pack(pady=10)

        # Save button
        def save_entry():
            # Validate required fields
            name = entries["name"].get().strip()
            password = entries["password"].get()

            if not name:
                status_var.set("❌ Name is required")
                return

            if not password:
                status_var.set("❌ Password is required")
                return

            # Get other fields
            username = entries["username"].get().strip()
            url = entries["url"].get().strip()
            notes = (
                entries["notes"].get(1.0, tk.END).strip() if "notes" in entries else ""
            )
            tags_str = entries["tags"].get().strip()
            tags = [tag.strip() for tag in tags_str.split(",")] if tags_str else []

            # Save entry (insert_password will replace due to same name)
            status_var.set("💾 Saving password...")
            dialog.update()

            def save_thread():
                try:
                    storage.insert_password(
                        master_password=master_password,
                        name=name,
                        password=password,
                        username=username if username else None,
                        url=url if url else None,
                        notes=notes if notes else None,
                        tags=tags if tags else None,
                    )

                    # Refresh list
                    self.load_entries()
                    self.filtered_entries = self.entries.copy()
                    self.update_entries_list()

                    # Close dialog
                    dialog.after(0, dialog.destroy)
                    self.status_var.set(f"✅ Updated '{name}'")

                except Exception as e:
                    status_var.set(f"❌ Error: {str(e)}")

            threading.Thread(target=save_thread, daemon=True).start()

        save_btn = ttk.Button(
            dialog, text="Save Changes", style="Accent.TButton", command=save_entry
        )
        save_btn.pack(pady=20)

        # Bind Enter key to save
        dialog.bind("<Return>", lambda e: save_entry())

        # Focus password field (password entry widget not stored, skip focus)

    def delete_current_entry(self):
        """Delete currently selected entry"""
        if not self.master_password or not self.storage:
            messagebox.showerror("Error", "Not authenticated")
            return

        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "No entry selected")
            return

        item = self.tree.item(selection[0])
        entry_name = item["values"][0]

        confirm = messagebox.askyesno(
            "Confirm Delete", f"Are you sure you want to delete '{entry_name}'?"
        )

        if confirm:
            try:
                if self.storage.delete_password(self.master_password, entry_name):
                    # Refresh list
                    self.load_entries()
                    self.filtered_entries = self.entries.copy()
                    self.update_entries_list()
                    self.status_var.set(f"🗑️  Deleted '{entry_name}'")
                else:
                    messagebox.showerror("Error", f"Failed to delete '{entry_name}'")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete: {e}")

    def show_export_dialog(self):
        """Show export dialog with recovery key options"""
        if not self.master_password or not self.storage:
            messagebox.showerror("Error", "Not authenticated")
            return
        assert self.master_password is not None
        assert self.storage is not None
        storage = self.storage
        master_password = self.master_password

        dialog = tk.Toplevel(self.root)
        dialog.title("Export Vault")
        dialog.geometry("600x500")
        dialog.configure(bg=self.bg_color)
        dialog.transient(self.root)
        dialog.grab_set()

        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = (
            self.root.winfo_y()
            + (self.root.winfo_height() - dialog.winfo_height()) // 2
        )
        dialog.geometry(f"+{x}+{y}")

        # Title
        title = ttk.Label(dialog, text="Export Password Vault", style="Title.TLabel")
        title.pack(pady=20)

        # Export type selection
        type_frame = ttk.Frame(dialog, style="Normal.TLabel")
        type_frame.pack(pady=20)

        export_type = tk.StringVar(value="standard")

        standard_radio = ttk.Radiobutton(
            type_frame,
            text="Standard Export",
            variable=export_type,
            value="standard",
            style="Normal.TLabel",
        )
        standard_radio.pack(anchor="w", pady=5)

        standard_desc = ttk.Label(
            type_frame,
            text="Encrypted with your master password only.",
            style="Normal.TLabel",
        )
        standard_desc.pack(anchor="w", padx=20)

        recovery_radio = ttk.Radiobutton(
            type_frame,
            text="Export with Recovery Key",
            variable=export_type,
            value="recovery",
            style="Normal.TLabel",
        )
        recovery_radio.pack(anchor="w", pady=5)

        recovery_desc = ttk.Label(
            type_frame,
            text="Creates a recovery key for emergency access.\n"
            "Generates two files: vault export + recovery key.",
            style="Normal.TLabel",
        )
        recovery_desc.pack(anchor="w", padx=20)

        # File selection
        file_frame = ttk.Frame(dialog, style="Normal.TLabel")
        file_frame.pack(pady=20)

        ttk.Label(file_frame, text="Export File:", style="Normal.TLabel").pack(
            side=tk.LEFT
        )
        file_var = tk.StringVar()
        file_entry = ttk.Entry(file_frame, textvariable=file_var, width=40)
        file_entry.pack(side=tk.LEFT, padx=10)

        def browse_file():
            from tkinter import filedialog

            filename = filedialog.asksaveasfilename(
                title="Save export file",
                defaultextension=".lox",
                filetypes=[("Lox export files", "*.lox"), ("All files", "*.*")],
            )
            if filename:
                file_var.set(filename)

        browse_btn = ttk.Button(file_frame, text="Browse...", command=browse_file)
        browse_btn.pack(side=tk.LEFT)

        # Status label
        status_var = tk.StringVar(value="")
        status_label = ttk.Label(dialog, textvariable=status_var, style="Normal.TLabel")
        status_label.pack(pady=10)

        # Export button
        def perform_export():
            filename = file_var.get().strip()
            if not filename:
                status_var.set("❌ Please select export file location")
                return

            export_type_val = export_type.get()

            def export_thread():
                try:
                    if export_type_val == "standard":
                        storage.export_encrypted(master_password, filename)
                        status_var.set("✅ Vault exported successfully")
                        dialog.after(2000, dialog.destroy)
                        self.status_var.set(f"✅ Vault exported to {filename}")
                    else:
                        recovery_key = storage.export_with_recovery_key(
                            master_password, filename
                        )
                        status_var.set(
                            f"✅ Vault exported with recovery key\n"
                            f"Recovery key saved to {filename}.recovery.key"
                        )
                        # Show recovery key warning
                        dialog.after(
                            0,
                            lambda: messagebox.showwarning(
                                "Recovery Key Generated",
                                f"Emergency recovery key generated:\n\n"
                                f"{recovery_key}\n\n"
                                f"Keep this key secure! It can decrypt your vault\n"
                                f"if you forget your master password.\n\n"
                                f"Also saved to: {filename}.recovery.key",
                            ),
                        )
                        dialog.after(3000, dialog.destroy)
                        self.status_var.set(f"✅ Vault exported with recovery key")

                except Exception as e:
                    status_var.set(f"❌ Export failed: {str(e)}")

            status_var.set("💾 Exporting vault...")
            threading.Thread(target=export_thread, daemon=True).start()

        export_btn = ttk.Button(
            dialog, text="Export Vault", style="Accent.TButton", command=perform_export
        )
        export_btn.pack(pady=20)

        # Bind Enter key
        dialog.bind("<Return>", lambda e: perform_export())

        # Focus file entry
        file_entry.focus_set()

    def show_import_dialog(self):
        """Show import dialog"""
        if not self.master_password or not self.storage:
            messagebox.showerror("Error", "Not authenticated")
            return
        assert self.master_password is not None
        assert self.storage is not None
        storage = self.storage
        master_password = self.master_password

        dialog = tk.Toplevel(self.root)
        dialog.title("Import Vault")
        dialog.geometry("500x300")
        dialog.configure(bg=self.bg_color)
        dialog.transient(self.root)
        dialog.grab_set()

        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = (
            self.root.winfo_y()
            + (self.root.winfo_height() - dialog.winfo_height()) // 2
        )
        dialog.geometry(f"+{x}+{y}")

        # Title
        title = ttk.Label(dialog, text="Import Password Vault", style="Title.TLabel")
        title.pack(pady=20)

        # File selection
        file_frame = ttk.Frame(dialog, style="Normal.TLabel")
        file_frame.pack(pady=20)

        ttk.Label(file_frame, text="Import File:", style="Normal.TLabel").pack(
            side=tk.LEFT
        )
        file_var = tk.StringVar()
        file_entry = ttk.Entry(file_frame, textvariable=file_var, width=40)
        file_entry.pack(side=tk.LEFT, padx=10)

        def browse_file():
            from tkinter import filedialog

            filename = filedialog.askopenfilename(
                title="Select export file",
                filetypes=[
                    ("Lox export files", "*.lox"),
                    ("Database files", "*.db"),
                    ("All files", "*.*"),
                ],
            )
            if filename:
                file_var.set(filename)

        browse_btn = ttk.Button(file_frame, text="Browse...", command=browse_file)
        browse_btn.pack(side=tk.LEFT)

        # Import options
        options_frame = ttk.Frame(dialog, style="Normal.TLabel")
        options_frame.pack(pady=10)

        conflict_var = tk.StringVar(value="overwrite")
        ttk.Radiobutton(
            options_frame,
            text="Overwrite duplicates",
            variable=conflict_var,
            value="overwrite",
            style="Normal.TLabel",
        ).pack(anchor="w")
        ttk.Radiobutton(
            options_frame,
            text="Skip duplicates",
            variable=conflict_var,
            value="skip",
            style="Normal.TLabel",
        ).pack(anchor="w")

        # Status label
        status_var = tk.StringVar(value="")
        status_label = ttk.Label(dialog, textvariable=status_var, style="Normal.TLabel")
        status_label.pack(pady=10)

        # Import button
        def perform_import():
            filename = file_var.get().strip()
            if not filename:
                status_var.set("❌ Please select import file")
                return

            def import_thread():
                try:
                    imported = storage.import_encrypted(master_password, filename)
                    status_var.set(f"✅ Imported {imported} entries")
                    # Refresh list
                    self.load_entries()
                    self.filtered_entries = self.entries.copy()
                    self.update_entries_list()
                    dialog.after(2000, dialog.destroy)
                    self.status_var.set(f"✅ Imported {imported} entries")
                except Exception as e:
                    status_var.set(f"❌ Import failed: {str(e)}")

            status_var.set("📥 Importing vault...")
            threading.Thread(target=import_thread, daemon=True).start()

        import_btn = ttk.Button(
            dialog, text="Import Vault", style="Accent.TButton", command=perform_import
        )
        import_btn.pack(pady=20)

        # Bind Enter key
        dialog.bind("<Return>", lambda e: perform_import())

        # Focus file entry
        file_entry.focus_set()

    def lock_vault(self):
        """Lock the vault and return to login screen"""
        self.storage = None
        self.master_password = None
        self.session = None
        self.entries = []
        self.filtered_entries = []

        # Clear clipboard
        try:
            import pyperclip

            pyperclip.copy("")
        except:
            pass

        self.show_login_screen()
        self.status_var.set("Vault locked")

    def run(self):
        """Start the GUI application"""
        self.root.mainloop()


def main():
    """Main entry point for GUI"""
    app = LoxGUI()
    app.run()


if __name__ == "__main__":
    main()
