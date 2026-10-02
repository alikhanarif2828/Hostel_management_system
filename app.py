import streamlit as st
import sqlite3
import hashlib
import secrets
import string
import pandas as pd
from datetime import datetime

# Attempt to use bcrypt; fallback gracefully to hashlib SHA256 if not installed
try:
    import bcrypt
    USE_BCRYPT = True
except ImportError:
    USE_BCRYPT = False

# ==========================================
# DATABASE INITIALIZATION & HELPERS
# ==========================================
DB_FILE = "hostel_system.db"

def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def hash_pw(plain: str) -> str:
    if USE_BCRYPT:
        return bcrypt.hashpw(plain.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    return "sha256$" + hashlib.sha256(plain.encode('utf-8')).hexdigest()

def check_pw(plain: str, hashed: str) -> bool:
    try:
        if hashed.startswith("sha256$"):
            return ("sha256$" + hashlib.sha256(plain.encode('utf-8')).hexdigest()) == hashed
        if USE_BCRYPT:
            return bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))
        return False
    except Exception:
        return False

def generate_temp_password(length=8) -> str:
    alphabet = string.ascii_letters + string.digits + "@#$%"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # 1. Branches
    c.execute('''
        CREATE TABLE IF NOT EXISTS branches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            code TEXT UNIQUE NOT NULL,
            city TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 2. Rooms
    c.execute('''
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            branch_id INTEGER NOT NULL,
            room_number TEXT NOT NULL,
            floor TEXT DEFAULT 'Ground Floor',
            FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE CASCADE
        )
    ''')

    # 3. Users (Owner, Staff, Client)
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_code TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            branch_id INTEGER,
            room_id INTEGER,
            assigned_floor TEXT DEFAULT 'All Floors',
            rent_amount REAL DEFAULT 0.0,
            salary_amount REAL DEFAULT 0.0,
            must_change_password BOOLEAN DEFAULT 0,
            reset_requested BOOLEAN DEFAULT 0,
            reset_note TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (branch_id) REFERENCES branches(id),
            FOREIGN KEY (room_id) REFERENCES rooms(id)
        )
    ''')

    # 4. Service / Complaint Requests
    c.execute('''
        CREATE TABLE IF NOT EXISTS service_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            branch_id INTEGER NOT NULL,
            room_id INTEGER NOT NULL,
            client_id INTEGER NOT NULL,
            assigned_staff_id INTEGER,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'Pending',
            resolution_notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (branch_id) REFERENCES branches(id),
            FOREIGN KEY (room_id) REFERENCES rooms(id),
            FOREIGN KEY (client_id) REFERENCES users(id),
            FOREIGN KEY (assigned_staff_id) REFERENCES users(id)
        )
    ''')

    # 5. Rent Notices / Invoices
    c.execute('''
        CREATE TABLE IF NOT EXISTS rent_notices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            branch_id INTEGER NOT NULL,
            billing_month TEXT NOT NULL,
            amount REAL NOT NULL,
            due_date TEXT NOT NULL,
            status TEXT DEFAULT 'Unpaid',
            notice_message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (client_id) REFERENCES users(id),
            FOREIGN KEY (branch_id) REFERENCES branches(id)
        )
    ''')

    # 6. Salary Records
    c.execute('''
        CREATE TABLE IF NOT EXISTS salary_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            staff_id INTEGER NOT NULL,
            branch_id INTEGER NOT NULL,
            pay_month TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT DEFAULT 'Paid',
            payment_date TEXT,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (staff_id) REFERENCES users(id),
            FOREIGN KEY (branch_id) REFERENCES branches(id)
        )
    ''')

    # Safe Schema Migrations
    user_cols = [row["name"] for row in c.execute("PRAGMA table_info(users)").fetchall()]
    if "reset_requested" not in user_cols:
        c.execute("ALTER TABLE users ADD COLUMN reset_requested BOOLEAN DEFAULT 0")
    if "reset_note" not in user_cols:
        c.execute("ALTER TABLE users ADD COLUMN reset_note TEXT")
    if "assigned_floor" not in user_cols:
        c.execute("ALTER TABLE users ADD COLUMN assigned_floor TEXT DEFAULT 'All Floors'")
    if "rent_amount" not in user_cols:
        c.execute("ALTER TABLE users ADD COLUMN rent_amount REAL DEFAULT 0.0")
    if "salary_amount" not in user_cols:
        c.execute("ALTER TABLE users ADD COLUMN salary_amount REAL DEFAULT 0.0")

    room_cols = [row["name"] for row in c.execute("PRAGMA table_info(rooms)").fetchall()]
    if "floor" not in room_cols:
        c.execute("ALTER TABLE rooms ADD COLUMN floor TEXT DEFAULT 'Ground Floor'")

    # Default Super Admin Account
    c.execute("SELECT id FROM users WHERE role = 'owner'")
    if not c.fetchone():
        c.execute('''
            INSERT INTO users (user_code, full_name, password_hash, role, must_change_password)
            VALUES (?, ?, ?, 'owner', 0)
        ''', ("OWNER001", "Super Admin", hash_pw("Owner@1234")))

    conn.commit()
    conn.close()

init_db()

# ==========================================
# STATE & CACHING
# ==========================================
if "user" not in st.session_state:
    st.session_state.user = None
if "auth_mode" not in st.session_state:
    st.session_state.auth_mode = "login"

STANDARD_FLOORS = [
    "Basement", 
    "Ground Floor", 
    "1st Floor", 
    "2nd Floor", 
    "3rd Floor", 
    "4th Floor", 
    "5th Floor"
]

# ==========================================
# AUTHENTICATION & RECOVERY VIEWS
# ==========================================
def login_view():
    st.markdown("## 🏨 Hostel Management System")
    st.caption("Multi-Branch Portal with Operations, Floor Assignments & Financial Control")
    st.write("---")

    col1, col2 = st.columns([1.2, 1])

    with col1:
        if st.session_state.auth_mode == "login":
            st.subheader("Account Sign In")
            with st.form("login_form"):
                user_code = st.text_input("User ID / Login Code", placeholder="e.g. OWNER001, GLB-C0001, GLB-E0001")
                password = st.text_input("Password", type="password")
                submit = st.form_submit_button("Sign In", use_container_width=True, type="primary")

                if submit:
                    if not user_code or not password:
                        st.warning("Please provide both User ID and Password.")
                    else:
                        conn = get_db()
                        c = conn.cursor()
                        c.execute("SELECT * FROM users WHERE user_code = ?", (user_code.strip(),))
                        user_record = c.fetchone()
                        conn.close()

                        if user_record and check_pw(password, user_record["password_hash"]):
                            st.session_state.user = dict(user_record)
                            st.success("Authenticated successfully!")
                            st.rerun()
                        else:
                            st.error("Invalid User ID or Password.")

            if st.button("Forgot Password? Request Reset from Owner"):
                st.session_state.auth_mode = "forgot_password"
                st.rerun()

        elif st.session_state.auth_mode == "forgot_password":
            st.subheader("🔑 Request Password Reset")
            st.info("Submit your registered details below. The Owner will issue a new temporary password.")

            with st.form("forgot_pw_form"):
                req_code = st.text_input("Your User ID", placeholder="e.g. GLB-C0001")
                req_name = st.text_input("Your Registered Full Name")
                req_note = st.text_area("Reason / Note (Optional)", placeholder="e.g. Forgot password")
                submit_req = st.form_submit_button("Submit Reset Request", type="primary", use_container_width=True)

                if submit_req:
                    if not req_code or not req_name:
                        st.error("Please supply both your User ID and Name.")
                    else:
                        conn = get_db()
                        c = conn.cursor()
                        c.execute("SELECT id FROM users WHERE user_code = ? AND LOWER(full_name) = LOWER(?)", 
                                  (req_code.strip(), req_name.strip()))
                        matched_user = c.fetchone()

                        if matched_user:
                            c.execute("""
                                UPDATE users 
                                SET reset_requested = 1, reset_note = ? 
                                WHERE id = ?
                            """, (req_note.strip() if req_note else "Password reset requested", matched_user["id"]))
                            conn.commit()
                            st.success("Request logged. Please contact your hostel owner for your new password.")
                        else:
                            st.error("No account matching that User ID and Name was found.")
                        conn.close()

            if st.button("← Back to Login"):
                st.session_state.auth_mode = "login"
                st.rerun()

    with col2:
        st.info(
            "🔑 **System Access & Governance**\n\n"
            "- **Super Admin / Owner:** Authorized administrators only.\n"
            "- **Residents:** View rent due notices, payment receipts, and issue maintenance complaints.\n"
            "- **Employees:** View assigned floor duties, tasks, and monthly salary slips.\n"
            "- **Offboarding:** Leaving residents or employees can be removed cleanly by the Owner."
        )

def change_password_view():
    st.markdown("### 🔒 Password Reset Required")
    st.warning("You are currently using a temporary password. You must set a personal password to access the portal.")

    with st.form("pwd_reset_form"):
        new_pw = st.text_input("New Password", type="password")
        confirm_pw = st.text_input("Confirm New Password", type="password")
        btn = st.form_submit_button("Save New Password", type="primary")

        if btn:
            if len(new_pw) < 6:
                st.error("Password must be at least 6 characters long.")
            elif new_pw != confirm_pw:
                st.error("Passwords do not match.")
            else:
                conn = get_db()
                c = conn.cursor()
                c.execute("""
                    UPDATE users 
                    SET password_hash = ?, must_change_password = 0, reset_requested = 0, reset_note = NULL
                    WHERE id = ?
                """, (hash_pw(new_pw), st.session_state.user["id"]))
                conn.commit()
                conn.close()

                st.session_state.user["must_change_password"] = 0
                st.success("Password updated successfully!")
                st.rerun()

# ==========================================
# OWNER DASHBOARD
# ==========================================
def owner_dashboard():
    st.sidebar.markdown(f"### 👤 {st.session_state.user['full_name']}")
    st.sidebar.caption("Role: System Owner")

    conn = get_db()
    c = conn.cursor()

    reset_count = c.execute("SELECT COUNT(*) as count FROM users WHERE reset_requested = 1").fetchone()["count"]
    reset_label = f"Password Resets ({reset_count})" if reset_count > 0 else "Password Resets"

    menu = st.sidebar.radio("Navigation", [
        "Maintenance & Cleaning",
        "Finance: Rent & Salaries",
        reset_label,
        "Provision Accounts",
        "Branches & Bulk Rooms",
        "Directory & Offboarding"
    ])

    # --- 1. TICKET TRIAGE ---
    if menu == "Maintenance & Cleaning":
        st.subheader("📋 Maintenance & Cleaning Tickets")
        
        total_tickets = c.execute("SELECT COUNT(*) as count FROM service_requests").fetchone()["count"]
        pending = c.execute("SELECT COUNT(*) as count FROM service_requests WHERE status = 'Pending'").fetchone()["count"]
        resolved = c.execute("SELECT COUNT(*) as count FROM service_requests WHERE status = 'Resolved'").fetchone()["count"]

        m1, m2, m3 = st.columns(3)
        m1.metric("Total Tickets", total_tickets)
        m2.metric("Pending Action", pending)
        m3.metric("Resolved", resolved)
        st.write("---")

        branches = c.execute("SELECT id, name FROM branches").fetchall()
        branch_map = {b["name"]: b["id"] for b in branches}
        selected_b_name = st.selectbox("Filter Branch", ["All Branches"] + list(branch_map.keys()))

        query = """
            SELECT r.id, b.name as branch_name, rm.room_number, rm.floor, u.full_name as client_name,
                   r.category, r.title, r.description, r.status, s.full_name as staff_name,
                   r.resolution_notes, r.created_at
            FROM service_requests r
            JOIN branches b ON r.branch_id = b.id
            JOIN rooms rm ON r.room_id = rm.id
            JOIN users u ON r.client_id = u.id
            LEFT JOIN users s ON r.assigned_staff_id = s.id
        """
        params = []
        if selected_b_name != "All Branches":
            query += " WHERE r.branch_id = ?"
            params.append(branch_map[selected_b_name])

        query += " ORDER BY r.id DESC"
        tickets = c.execute(query, params).fetchall()

        if not tickets:
            st.info("No service requests recorded.")
        else:
            staff_list = c.execute("SELECT id, full_name, user_code, assigned_floor FROM users WHERE role = 'staff'").fetchall()
            staff_dict = {f"{s['full_name']} ({s['user_code']}) [Floors: {s['assigned_floor']}]": s["id"] for s in staff_list}

            for t in tickets:
                status_color = "🟠" if t['status'] == 'Pending' else ("🔵" if t['status'] == 'Assigned' else "🟢")
                with st.expander(f"{status_color} [{t['status'].upper()}] #{t['id']} - {t['title']} ({t['branch_name']} | {t['floor']} - Room {t['room_number']})"):
                    st.write(f"**Floor / Room:** {t['floor']} / Room {t['room_number']}")
                    st.write(f"**Category:** {t['category']} | **Reported By:** {t['client_name']} ({t['created_at']})")
                    st.write(f"**Details:** {t['description']}")
                    st.write(f"**Current Assignee:** `{t['staff_name'] or 'None'}`")
                    
                    if t["resolution_notes"]:
                        st.success(f"**Resolution Notes:** {t['resolution_notes']}")

                    if staff_dict:
                        st.markdown("---")
                        c_a, c_b = st.columns([3, 1])
                        with c_a:
                            selected_staff = st.selectbox(
                                "Assign Employee",
                                list(staff_dict.keys()),
                                key=f"assign_staff_{t['id']}"
                            )
                        with c_b:
                            st.write("")
                            st.write("")
                            if st.button("Assign", key=f"btn_assign_{t['id']}", use_container_width=True):
                                c.execute("""
                                    UPDATE service_requests 
                                    SET assigned_staff_id = ?, status = 'Assigned' 
                                    WHERE id = ?
                                """, (staff_dict[selected_staff], t["id"]))
                                conn.commit()
                                st.success("Assigned!")
                                st.rerun()

    # --- 2. FINANCE: BRANCH COLLECTIONS, RENT & SALARIES ---
    elif menu == "Finance: Rent & Salaries":
        st.subheader("💰 Financial Analytics & Branch Rent Collections")

        st.markdown("### 🏢 Rent Collection by Branch")
        branch_stats = c.execute("""
            SELECT 
                b.id,
                b.name as branch_name,
                b.city,
                COUNT(rn.id) as total_notices,
                COALESCE(SUM(rn.amount), 0) as total_billed,
                COALESCE(SUM(CASE WHEN rn.status = 'Paid' THEN rn.amount ELSE 0 END), 0) as total_collected,
                COALESCE(SUM(CASE WHEN rn.status = 'Unpaid' THEN rn.amount ELSE 0 END), 0) as total_pending
            FROM branches b
            LEFT JOIN rent_notices rn ON b.id = rn.branch_id
            GROUP BY b.id
        """).fetchall()

        if not branch_stats:
            st.info("No branches or rent records found.")
        else:
            tot_billed_all = sum(b["total_billed"] for b in branch_stats)
            tot_collected_all = sum(b["total_collected"] for b in branch_stats)
            tot_pending_all = sum(b["total_pending"] for b in branch_stats)
            recovery_rate = (tot_collected_all / tot_billed_all * 100) if tot_billed_all > 0 else 0.0

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Total Billed", f"Rs. {tot_billed_all:,.0f}")
            m2.metric("Total Collected", f"Rs. {tot_collected_all:,.0f}")
            m3.metric("Pending Balance", f"Rs. {tot_pending_all:,.0f}")
            m4.metric("Overall Recovery", f"{recovery_rate:.1f}%")

            summary_data = []
            for b in branch_stats:
                rate = (b["total_collected"] / b["total_billed"] * 100) if b["total_billed"] > 0 else 0.0
                summary_data.append({
                    "Branch Name": f"{b['branch_name']} ({b['city']})",
                    "Notices Issued": b["total_notices"],
                    "Total Billed (PKR)": f"Rs. {b['total_billed']:,.2f}",
                    "Rent Collected (PKR)": f"Rs. {b['total_collected']:,.2f}",
                    "Pending Due (PKR)": f"Rs. {b['total_pending']:,.2f}",
                    "Recovery Rate": f"{rate:.1f}%"
                })
            st.dataframe(pd.DataFrame(summary_data), use_container_width=True)

        st.write("---")

        tab_rent, tab_salary = st.tabs(["📢 Issue Rent Notices & Ledger", "💼 Employee Salaries & Payroll"])

        with tab_rent:
            st.markdown("#### 1. Issue Rent Notice to Resident")
            clients = c.execute("""
                SELECT u.id, u.full_name, u.user_code, u.rent_amount, b.name as branch_name, u.branch_id, r.room_number 
                FROM users u
                JOIN branches b ON u.branch_id = b.id
                LEFT JOIN rooms r ON u.room_id = r.id
                WHERE u.role = 'client'
            """).fetchall()

            if not clients:
                st.info("No residents registered yet.")
            else:
                client_dict = {f"{c_u['full_name']} ({c_u['user_code']} - {c_u['branch_name']} Rm {c_u['room_number']})": c_u for c_u in clients}
                
                with st.form("rent_notice_form"):
                    selected_c_label = st.selectbox("Select Resident", list(client_dict.keys()))
                    chosen_client = client_dict[selected_c_label]

                    col_r1, col_r2 = st.columns(2)
                    with col_r1:
                        billing_month = st.selectbox("Billing Month", [
                            "January", "February", "March", "April", "May", "June", 
                            "July", "August", "September", "October", "November", "December"
                        ], index=datetime.now().month - 1)
                        notice_amount = st.number_input("Rent Fair Amount (PKR)", value=float(chosen_client["rent_amount"]), step=500.0)
                    with col_r2:
                        due_date = st.date_input("Payment Due Date")
                        notice_msg = st.text_input("Notice Note / Message", value="Please clear rent before due date.")

                    send_notice_btn = st.form_submit_button("Send Rent Notice", type="primary", use_container_width=True)

                    if send_notice_btn:
                        c.execute("""
                            INSERT INTO rent_notices (client_id, branch_id, billing_month, amount, due_date, status, notice_message)
                            VALUES (?, ?, ?, ?, ?, 'Unpaid', ?)
                        """, (chosen_client["id"], chosen_client["branch_id"], billing_month, notice_amount, str(due_date), notice_msg))
                        conn.commit()
                        st.success(f"Rent notice for {billing_month} sent successfully to {chosen_client['full_name']}!")
                        st.rerun()

            st.write("---")
            st.markdown("#### 2. Detailed Branch Rent Tracker")
            
            all_b = c.execute("SELECT id, name FROM branches").fetchall()
            b_opts = {b["name"]: b["id"] for b in all_b}
            chosen_filter_b = st.selectbox("Filter Invoices by Branch", ["All Branches"] + list(b_opts.keys()))

            query_ledger = """
                SELECT rn.id, u.full_name, u.user_code, b.name as branch_name, rn.billing_month, 
                       rn.amount, rn.due_date, rn.status, rn.created_at
                FROM rent_notices rn
                JOIN users u ON rn.client_id = u.id
                JOIN branches b ON rn.branch_id = b.id
            """
            l_params = []
            if chosen_filter_b != "All Branches":
                query_ledger += " WHERE rn.branch_id = ?"
                l_params.append(b_opts[chosen_filter_b])
            query_ledger += " ORDER BY rn.id DESC"

            rent_records = c.execute(query_ledger, l_params).fetchall()

            if rent_records:
                for r_rec in rent_records:
                    status_badge = "🟢 Paid" if r_rec["status"] == "Paid" else "🔴 Unpaid"
                    with st.expander(f"{status_badge} | {r_rec['branch_name']} — {r_rec['full_name']} ({r_rec['user_code']}) — {r_rec['billing_month']} — Rs. {r_rec['amount']:,.2f}"):
                        st.write(f"**Branch:** {r_rec['branch_name']} | **Due Date:** {r_rec['due_date']}")
                        st.write(f"**Notice Issued:** {r_rec['created_at']}")
                        
                        col_btn1, col_btn2 = st.columns([3, 1])
                        with col_btn2:
                            new_st = "Paid" if r_rec["status"] == "Unpaid" else "Unpaid"
                            btn_label = "Mark as Paid" if r_rec["status"] == "Unpaid" else "Mark as Unpaid"
                            if st.button(btn_label, key=f"rent_status_toggle_{r_rec['id']}", use_container_width=True):
                                c.execute("UPDATE rent_notices SET status = ? WHERE id = ?", (new_st, r_rec["id"]))
                                conn.commit()
                                st.rerun()
            else:
                st.caption("No rent notices found for this selection.")

        with tab_salary:
            st.markdown("#### 1. Disburse Employee Salary")
            staff_members = c.execute("""
                SELECT u.id, u.full_name, u.user_code, u.salary_amount, b.name as branch_name, u.branch_id, u.assigned_floor
                FROM users u
                JOIN branches b ON u.branch_id = b.id
                WHERE u.role = 'staff'
            """).fetchall()

            if not staff_members:
                st.info("No employees registered yet.")
            else:
                staff_map = {f"{s['full_name']} ({s['user_code']} - {s['branch_name']})": s for s in staff_members}
                
                with st.form("salary_form"):
                    chosen_s_label = st.selectbox("Select Employee", list(staff_map.keys()))
                    chosen_staff = staff_map[chosen_s_label]

                    col_s1, col_s2 = st.columns(2)
                    with col_s1:
                        pay_month = st.selectbox("Salary Month", [
                            "January", "February", "March", "April", "May", "June", 
                            "July", "August", "September", "October", "November", "December"
                        ], index=datetime.now().month - 1)
                        salary_pay = st.number_input("Disbursed Salary (PKR)", value=float(chosen_staff["salary_amount"]), step=500.0)
                    with col_s2:
                        pay_date = st.date_input("Disbursement Date")
                        salary_notes = st.text_input("Payment Method / Notes", value="Cash / Bank Transfer")

                    disburse_btn = st.form_submit_button("Record Salary Payment", type="primary", use_container_width=True)

                    if disburse_btn:
                        c.execute("""
                            INSERT INTO salary_records (staff_id, branch_id, pay_month, amount, status, payment_date, notes)
                            VALUES (?, ?, ?, ?, 'Paid', ?, ?)
                        """, (chosen_staff["id"], chosen_staff["branch_id"], pay_month, salary_pay, str(pay_date), salary_notes))
                        conn.commit()
                        st.success(f"Salary payment of Rs. {salary_pay:,.2f} recorded for {chosen_staff['full_name']}!")
                        st.rerun()

            st.write("---")
            st.markdown("#### 2. Staff Payroll History")
            salaries = c.execute("""
                SELECT sr.id, u.full_name, u.user_code, b.name as branch_name, sr.pay_month, 
                       sr.amount, sr.payment_date, sr.notes
                FROM salary_records sr
                JOIN users u ON sr.staff_id = u.id
                JOIN branches b ON sr.branch_id = b.id
                ORDER BY sr.id DESC
            """).fetchall()

            if salaries:
                df_sal = pd.DataFrame([dict(r) for r in salaries])
                df_sal.columns = ["ID", "Employee Name", "Code", "Branch", "Month", "Amount (PKR)", "Payment Date", "Notes"]
                st.dataframe(df_sal, use_container_width=True)
            else:
                st.caption("No salary disbursements logged yet.")

    # --- 3. PASSWORD RESET REQUESTS ---
    elif "Password Resets" in menu:
        st.subheader("🔑 Password Reset Requests (Forgotten Passwords)")
        st.caption("Review requests from clients or employees and issue new temporary credentials.")

        requests = c.execute("""
            SELECT u.id, u.user_code, u.full_name, u.role, b.name as branch_name, 
                   COALESCE(r.room_number, 'N/A') as room_number, u.reset_note
            FROM users u
            LEFT JOIN branches b ON u.branch_id = b.id
            LEFT JOIN rooms r ON u.room_id = r.id
            WHERE u.reset_requested = 1
        """).fetchall()

        if not requests:
            st.info("No pending password reset requests.")
        else:
            for req in requests:
                with st.expander(f"⚠️ {req['full_name']} ({req['user_code']}) - Role: {req['role'].upper()}"):
                    st.write(f"**Branch:** {req['branch_name']} | **Room:** {req['room_number']}")
                    st.write(f"**User Message:** {req['reset_note']}")

                    col_res1, col_res2 = st.columns([2, 1])
                    with col_res1:
                        admin_custom_pw = st.text_input("Custom Temp Password (leave blank for random)", key=f"reset_pw_{req['id']}")
                    with col_res2:
                        st.write("")
                        st.write("")
                        if st.button("Generate & Reset", key=f"btn_reset_{req['id']}", type="primary"):
                            temp_pw = admin_custom_pw.strip() if admin_custom_pw else generate_temp_password(8)
                            c.execute("""
                                UPDATE users 
                                SET password_hash = ?, must_change_password = 1, reset_requested = 0, reset_note = NULL
                                WHERE id = ?
                            """, (hash_pw(temp_pw), req["id"]))
                            conn.commit()

                            st.success(f"Password reset for {req['full_name']}!")
                            st.code(
                                f"User ID:           {req['user_code']}\n"
                                f"New Temp Password: {temp_pw}\n\n"
                                f"Hand this to the user. They will be forced to change it on login.",
                                language="text"
                            )

    # --- 4. PROVISION ACCOUNTS (WITH RENT FARE & SALARY) ---
    elif menu == "Provision Accounts":
        st.subheader("🔑 Provision Client / Employee Credentials")
        st.caption("Generate User IDs and passwords, configure Rent Fare for residents, and Monthly Salary for staff.")

        branches = c.execute("SELECT id, name, code FROM branches").fetchall()
        if not branches:
            st.warning("⚠️ You must add at least one branch before creating users.")
            conn.close()
            return

        branch_map = {f"{b['name']} ({b['code']})": b for b in branches}
        
        with st.form("provision_form"):
            role_type = st.radio("Account Type", ["Client (Resident)", "Employee (Staff)"], horizontal=True)
            branch_choice = st.selectbox("Select Branch", list(branch_map.keys()))
            selected_branch = branch_map[branch_choice]

            full_name = st.text_input("Full Name", placeholder="e.g. Tariq Mehmood")

            rooms = c.execute("SELECT id, room_number, floor FROM rooms WHERE branch_id = ? ORDER BY floor, room_number", (selected_branch["id"],)).fetchall()
            distinct_floors = sorted(list({r["floor"] for r in rooms if r["floor"]})) if rooms else STANDARD_FLOORS

            selected_room_id = None
            assigned_floor_choice = "All Floors"
            rent_val = 0.0
            salary_val = 0.0

            if "Client" in role_type:
                if not rooms:
                    st.warning("⚠️ No rooms exist in this branch yet. Add rooms first under 'Branches & Bulk Rooms'.")
                else:
                    room_map = {f"{r['floor']} - Room {r['room_number']}": r["id"] for r in rooms}
                    room_choice = st.selectbox("Assign Room", list(room_map.keys()))
                    selected_room_id = room_map[room_choice]
                
                rent_val = st.number_input("Monthly Rent Fare (PKR)", value=12000.0, step=500.0)
            else:
                st.markdown("##### 🏢 Select Employee Floor Responsibility")
                all_floors_toggle = st.checkbox("Assign to All Floors (Entire Branch)", value=True)
                
                if not all_floors_toggle:
                    selected_floors = st.multiselect(
                        "Pick one or more floors for this employee:",
                        distinct_floors,
                        default=[distinct_floors[0]] if distinct_floors else []
                    )
                    assigned_floor_choice = ", ".join(selected_floors) if selected_floors else "All Floors"
                else:
                    assigned_floor_choice = "All Floors"

                salary_val = st.number_input("Monthly Salary (PKR)", value=30000.0, step=1000.0)

            custom_pw = st.text_input("Custom Password (Optional - leave blank to auto-generate)", type="password")
            generate_btn = st.form_submit_button("Generate Account Credentials", type="primary", use_container_width=True)

            if generate_btn:
                if not full_name:
                    st.error("Please enter a name.")
                elif "Client" in role_type and not selected_room_id:
                    st.error("A room must be selected for client accounts.")
                else:
                    role = "client" if "Client" in role_type else "staff"
                    tag = "C" if role == "client" else "E"
                    display_role = "CLIENT" if role == "client" else "EMPLOYEE"

                    count = c.execute("SELECT COUNT(*) as cnt FROM users WHERE branch_id = ? AND role = ?", 
                                      (selected_branch["id"], role)).fetchone()["cnt"]
                    user_code = f"{selected_branch['code']}-{tag}{count + 1:04d}"
                    final_pw = custom_pw.strip() if custom_pw else generate_temp_password(8)

                    c.execute("""
                        INSERT INTO users (user_code, full_name, password_hash, role, branch_id, room_id, assigned_floor, rent_amount, salary_amount, must_change_password)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                    """, (user_code, full_name, hash_pw(final_pw), role, selected_branch["id"], selected_room_id, assigned_floor_choice, rent_val, salary_val))
                    conn.commit()

                    st.success("Account provisioned successfully!")
                    financial_info = f"Monthly Rent Fare:  Rs. {rent_val:,.2f}" if role == "client" else f"Monthly Salary:     Rs. {salary_val:,.2f}"
                    st.code(
                        f"====================================\n"
                        f"OFFICIAL HOSTEL CREDENTIAL SLIP\n"
                        f"====================================\n"
                        f"Name:               {full_name}\n"
                        f"Role:               {display_role}\n"
                        f"Branch:             {selected_branch['name']}\n"
                        f"{financial_info}\n"
                        f"User ID / Login ID: {user_code}\n"
                        f"Temporary Password: {final_pw}\n"
                        f"====================================\n"
                        f"Note: User will be prompted to reset password upon first login.",
                        language="text"
                    )

    # --- 5. BRANCH & BULK ROOM GENERATOR ---
    elif menu == "Branches & Bulk Rooms":
        st.subheader("🏢 Branch & Bulk Room Generator")
        c1, c2 = st.columns([1, 1.2])

        with c1:
            st.markdown("#### 1. Add Branch")
            with st.form("branch_form"):
                b_name = st.text_input("Branch Name", placeholder="e.g. Model Town Campus")
                b_code = st.text_input("Branch Code (Short)", placeholder="e.g. MTC")
                b_city = st.text_input("City", placeholder="e.g. Lahore")
                submit_b = st.form_submit_button("Create Branch", use_container_width=True)

                if submit_b:
                    if b_name and b_code and b_city:
                        try:
                            c.execute("INSERT INTO branches (name, code, city) VALUES (?, ?, ?)",
                                      (b_name.strip(), b_code.strip().upper(), b_city.strip()))
                            conn.commit()
                            st.success(f"Branch '{b_name}' created!")
                            st.rerun()
                        except sqlite3.IntegrityError:
                            st.error("Branch Code already exists. Please choose a distinct code.")
                    else:
                        st.warning("Please fill in all branch fields.")

        with c2:
            st.markdown("#### 2. Generate All Rooms in Floor")
            branches = c.execute("SELECT id, name FROM branches").fetchall()
            if not branches:
                st.info("Add a branch first to enable room creation.")
            else:
                b_dict = {b["name"]: b["id"] for b in branches}
                with st.form("bulk_room_form"):
                    chosen_b = st.selectbox("Select Branch", list(b_dict.keys()))
                    floor_name = st.selectbox("Floor", STANDARD_FLOORS)
                    
                    st.write("##### Room Generation Mode")
                    mode = st.radio("Choose Mode", ["Sequential Range (All Rooms in Floor)", "Single Specific Room"], horizontal=True)
                    
                    prefix = st.text_input("Room Prefix (Optional)", placeholder="e.g. F1- or leave blank")
                    
                    col_r1, col_r2 = st.columns(2)
                    with col_r1:
                        start_num = st.number_input("Start Room Number", min_value=1, max_value=999, value=101)
                    with col_r2:
                        end_num = st.number_input("End Room Number", min_value=1, max_value=999, value=110)
                        
                    submit_bulk = st.form_submit_button("Generate Floor Rooms", use_container_width=True, type="primary")

                    if submit_bulk:
                        branch_id = b_dict[chosen_b]
                        if mode == "Sequential Range (All Rooms in Floor)":
                            if start_num > end_num:
                                st.error("Start room number must be less than or equal to end room number.")
                            else:
                                created_count = 0
                                for n in range(int(start_num), int(end_num) + 1):
                                    r_label = f"{prefix.strip()}{n}"
                                    exists = c.execute("SELECT id FROM rooms WHERE branch_id = ? AND room_number = ?", 
                                                       (branch_id, r_label)).fetchone()
                                    if not exists:
                                        c.execute("INSERT INTO rooms (branch_id, room_number, floor) VALUES (?, ?, ?)",
                                                  (branch_id, r_label, floor_name))
                                        created_count += 1
                                conn.commit()
                                st.success(f"Successfully generated {created_count} rooms on {floor_name}!")
                                st.rerun()
                        else:
                            r_label = f"{prefix.strip()}{int(start_num)}"
                            c.execute("INSERT INTO rooms (branch_id, room_number, floor) VALUES (?, ?, ?)",
                                      (branch_id, r_label, floor_name))
                            conn.commit()
                            st.success(f"Room '{r_label}' created on {floor_name}!")
                            st.rerun()

    # --- 6. DIRECTORY & OFFBOARDING (DELETE INFO) ---
    elif menu == "Directory & Offboarding":
        st.subheader("👥 Resident & Employee Offboarding (Delete Accounts)")
        st.caption("When a resident leaves or staff resigns, you can permanently remove their records, vacate rooms, and reassign tasks.")

        # Tab 1: Clean Summary Table
        tab_list, tab_manage = st.tabs(["📋 Master Directory", "🗑️ Offboard / Delete User"])

        with tab_list:
            records = c.execute("""
                SELECT u.user_code, u.full_name, u.role, b.name as branch_name, 
                       COALESCE(r.floor, u.assigned_floor) as floor_coverage,
                       COALESCE(r.room_number, 'N/A') as room_number,
                       CASE WHEN u.role = 'client' THEN u.rent_amount ELSE u.salary_amount END as financial_rate,
                       u.created_at
                FROM users u
                LEFT JOIN branches b ON u.branch_id = b.id
                LEFT JOIN rooms r ON u.room_id = r.id
                WHERE u.role != 'owner'
                ORDER BY u.id DESC
            """).fetchall()

            if records:
                df = pd.DataFrame([dict(row) for row in records])
                df.columns = ["Login Code (ID)", "Name", "Role", "Branch", "Floor / Coverage", "Room", "Rent / Salary (PKR)", "Created At"]
                st.dataframe(df, use_container_width=True)
            else:
                st.info("No clients or employees provisioned yet.")

        with tab_manage:
            st.markdown("#### Permanent Departure / Checkout")
            st.warning("⚠️ Deleting an account revokes portal access, clears room occupancy for residents, and sets active employee tickets back to unassigned.")

            active_users = c.execute("""
                SELECT u.id, u.user_code, u.full_name, u.role, b.name as branch_name, 
                       COALESCE(r.room_number, 'N/A') as room_number
                FROM users u
                LEFT JOIN branches b ON u.branch_id = b.id
                LEFT JOIN rooms r ON u.room_id = r.id
                WHERE u.role != 'owner'
                ORDER BY u.role, u.full_name
            """).fetchall()

            if not active_users:
                st.info("No active residents or employees to delete.")
            else:
                user_lookup = {f"[{u['role'].upper()}] {u['full_name']} ({u['user_code']} - {u['branch_name']})": u for u in active_users}
                target_label = st.selectbox("Select Resident or Employee to Remove", list(user_lookup.keys()))
                target_user = user_lookup[target_label]

                with st.expander(f"Confirm Deletion for {target_user['full_name']} ({target_user['user_code']})", expanded=True):
                    st.write(f"- **Role:** {target_user['role'].title()}")
                    st.write(f"- **Branch:** {target_user['branch_name']}")
                    st.write(f"- **Room:** {target_user['room_number']}")

                    confirm_check = st.checkbox(f"I confirm that {target_user['full_name']} has left and I want to delete all their records permanently.", key=f"confirm_del_{target_user['id']}")

                    if st.button("🗑️ Permanently Delete & Offboard User", type="primary", key=f"del_btn_{target_user['id']}"):
                        if not confirm_check:
                            st.error("Please click the confirmation checkbox first.")
                        else:
                            uid = target_user["id"]
                            urole = target_user["role"]

                            if urole == "client":
                                # Remove client notices and tickets submitted by them
                                c.execute("DELETE FROM rent_notices WHERE client_id = ?", (uid,))
                                c.execute("DELETE FROM service_requests WHERE client_id = ?", (uid,))
                            elif urole == "staff":
                                # Revert any tickets currently assigned to this staff back to Pending
                                c.execute("""
                                    UPDATE service_requests 
                                    SET assigned_staff_id = NULL, status = 'Pending' 
                                    WHERE assigned_staff_id = ?
                                """, (uid,))
                                c.execute("DELETE FROM salary_records WHERE staff_id = ?", (uid,))

                            # Delete the user record
                            c.execute("DELETE FROM users WHERE id = ?", (uid,))
                            conn.commit()

                            st.success(f"{target_user['full_name']} has been successfully deleted from the system.")
                            st.rerun()

    conn.close()

# ==========================================
# CLIENT DASHBOARD (WITH RENT NOTICES & BILLS)
# ==========================================
def client_dashboard():
    u = st.session_state.user
    conn = get_db()
    c = conn.cursor()

    info = c.execute("""
        SELECT b.name as branch_name, r.room_number, r.floor 
        FROM rooms r 
        JOIN branches b ON r.branch_id = b.id 
        WHERE r.id = ?
    """, (u["room_id"],)).fetchone()

    branch_name = info["branch_name"] if info else "Unknown"
    room_number = info["room_number"] if info else "Unknown"
    floor_name = info["floor"] if info else "Unknown"

    st.sidebar.markdown(f"### 🛏️ Resident Portal")
    st.sidebar.write(f"**Resident:** {u['full_name']}")
    st.sidebar.write(f"**Your User ID:** `{u['user_code']}`")
    st.sidebar.write(f"**Branch:** {branch_name}")
    st.sidebar.write(f"**Room:** {floor_name} - Room {room_number}")
    st.sidebar.markdown(f"**Agreed Rent:** `PKR {u['rent_amount']:,.2f}`")

    tab_notices, tab_tickets = st.tabs(["📢 Rent Notices & Dues", "📝 Maintenance Requests"])

    with tab_notices:
        st.subheader("💵 My Rent Invoices & Notices")
        notices = c.execute("""
            SELECT id, billing_month, amount, due_date, status, notice_message, created_at
            FROM rent_notices
            WHERE client_id = ?
            ORDER BY id DESC
        """, (u["id"],)).fetchall()

        if not notices:
            st.info("🎉 No pending rent notices. You are all caught up!")
        else:
            for n in notices:
                badge = "🟢 Paid" if n["status"] == "Paid" else "🔴 Unpaid"
                with st.expander(f"{badge} | Rent Notice: {n['billing_month']} - Rs. {n['amount']:,.2f}"):
                    st.write(f"**Due Date:** {n['due_date']}")
                    st.write(f"**Owner Message:** {n['notice_message']}")
                    st.caption(f"Issued on: {n['created_at']}")
                    if n["status"] == "Unpaid":
                        st.warning("⚠️ Please submit payment to the hostel warden/owner before the due date.")

    with tab_tickets:
        st.subheader("Report Cleaning or Maintenance Issue")
        with st.form("client_ticket_form"):
            category = st.selectbox("Category", ["Cleaning", "Plumbing", "Electrical", "Wi-Fi / Internet", "Other"])
            title = st.text_input("Summary / Title", placeholder="e.g. Bathroom light bulb fused")
            description = st.text_area("Detailed Description", placeholder="Explain the issue...")
            submit = st.form_submit_button("Submit Request", type="primary", use_container_width=True)

            if submit:
                if not title or not description:
                    st.error("Please provide both a title and description.")
                else:
                    c.execute("""
                        INSERT INTO service_requests (branch_id, room_id, client_id, category, title, description, status)
                        VALUES (?, ?, ?, ?, ?, ?, 'Pending')
                    """, (u["branch_id"], u["room_id"], u["id"], category, title, description))
                    conn.commit()
                    st.success("Request submitted successfully!")
                    st.rerun()

        st.write("---")
        st.subheader("My Past Requests")
        my_tickets = c.execute("""
            SELECT r.id, r.category, r.title, r.description, r.status, 
                   s.full_name as staff_name, r.resolution_notes, r.created_at
            FROM service_requests r
            LEFT JOIN users s ON r.assigned_staff_id = s.id
            WHERE r.client_id = ?
            ORDER BY r.id DESC
        """, (u["id"],)).fetchall()

        if not my_tickets:
            st.info("You haven't filed any requests yet.")
        else:
            for t in my_tickets:
                with st.expander(f"[{t['status'].upper()}] {t['title']} — {t['created_at']}"):
                    st.write(f"**Category:** {t['category']}")
                    st.write(f"**Description:** {t['description']}")
                    st.write(f"**Assigned Person:** {t['staff_name'] or 'Pending Assignment'}")
                    if t["resolution_notes"]:
                        st.success(f"**Resolution Note:** {t['resolution_notes']}")

    conn.close()

# ==========================================
# STAFF DASHBOARD (WITH SALARY SLIPS)
# ==========================================
def staff_dashboard():
    u = st.session_state.user
    conn = get_db()
    c = conn.cursor()

    branch = c.execute("SELECT name FROM branches WHERE id = ?", (u["branch_id"],)).fetchone()
    branch_name = branch["name"] if branch else "N/A"
    assigned_floors_raw = u.get("assigned_floor") or "All Floors"

    st.sidebar.markdown(f"### 🔧 Employee Portal")
    st.sidebar.write(f"**Employee:** {u['full_name']}")
    st.sidebar.write(f"**Employee ID:** `{u['user_code']}`")
    st.sidebar.write(f"**Branch:** {branch_name}")
    st.sidebar.write(f"**Floor Coverage:** {assigned_floors_raw}")
    st.sidebar.markdown(f"**Monthly Salary:** `PKR {u['salary_amount']:,.2f}`")

    tab_tasks, tab_salary_slips = st.tabs(["🛠️ Tasks & Work Orders", "💼 Salary & Payslips"])

    with tab_tasks:
        st.subheader(f"Assigned Tasks ({assigned_floors_raw})")

        if "All Floors" in assigned_floors_raw:
            query = """
                SELECT r.id, rm.room_number, rm.floor, u.full_name as client_name, r.category,
                   r.title, r.description, r.status, r.resolution_notes, r.assigned_staff_id
                FROM service_requests r
                JOIN rooms rm ON r.room_id = rm.id
                JOIN users u ON r.client_id = u.id
                WHERE r.branch_id = ? AND (r.assigned_staff_id = ? OR r.status = 'Pending')
                ORDER BY r.id DESC
            """
            params = (u["branch_id"], u["id"])
        else:
            floor_list = [f.strip() for f in assigned_floors_raw.split(",") if f.strip()]
            placeholders = ",".join("?" for _ in floor_list)
            query = f"""
                SELECT r.id, rm.room_number, rm.floor, u.full_name as client_name, r.category,
                   r.title, r.description, r.status, r.resolution_notes, r.assigned_staff_id
                FROM service_requests r
                JOIN rooms rm ON r.room_id = rm.id
                JOIN users u ON r.client_id = u.id
                WHERE r.branch_id = ? 
                  AND (r.assigned_staff_id = ? OR (r.status = 'Pending' AND rm.floor IN ({placeholders})))
                ORDER BY r.id DESC
            """
            params = [u["branch_id"], u["id"]] + floor_list

        tasks = c.execute(query, params).fetchall()

        if not tasks:
            st.info("No active tickets on your assigned floor(s) right now.")
        else:
            for t in tasks:
                is_assigned = (t["assigned_staff_id"] == u["id"])
                tag = "Assigned to You" if is_assigned else f"Pending ({t['floor']})"
                
                with st.expander(f"[{t['status'].upper()}] {t['floor']} - Room {t['room_number']}: {t['title']} ({tag})"):
                    st.write(f"**Floor / Room:** {t['floor']} / Room {t['room_number']}")
                    st.write(f"**Category:** {t['category']} | **Resident:** {t['client_name']}")
                    st.write(f"**Description:** {t['description']}")
                    st.markdown("---")

                    current_status = t["status"]
                    status_opts = ["Pending", "In Progress", "Resolved"]
                    status_idx = status_opts.index(current_status) if current_status in status_opts else 0

                    new_status = st.selectbox("Change Status", status_opts, index=status_idx, key=f"status_sel_{t['id']}")
                    notes = st.text_area("Resolution / Action Notes", value=t["resolution_notes"] or "", key=f"notes_input_{t['id']}")

                    if st.button("Save Update", key=f"save_btn_{t['id']}", type="primary"):
                        c.execute("""
                            UPDATE service_requests 
                            SET status = ?, resolution_notes = ?, assigned_staff_id = COALESCE(assigned_staff_id, ?)
                            WHERE id = ?
                        """, (new_status, notes, u["id"], t["id"]))
                        conn.commit()
                        st.success("Ticket updated!")
                        st.rerun()

    with tab_salary_slips:
        st.subheader("💵 My Salary Slips")
        slips = c.execute("""
            SELECT pay_month, amount, status, payment_date, notes
            FROM salary_records
            WHERE staff_id = ?
            ORDER BY id DESC
        """, (u["id"],)).fetchall()

        if not slips:
            st.info("No salary records published yet.")
        else:
            df_slip = pd.DataFrame([dict(s) for s in slips])
            df_slip.columns = ["Month", "Salary Paid (PKR)", "Status", "Disbursement Date", "Notes"]
            st.dataframe(df_slip, use_container_width=True)

    conn.close()

# ==========================================
# MAIN APPLICATION ROUTER
# ==========================================
def main():
    st.set_page_config(
        page_title="Hostel Management Portal",
        page_icon="🏨",
        layout="wide"
    )

    if st.session_state.user:
        if st.sidebar.button("🚪 Logout", use_container_width=True):
            st.session_state.user = None
            st.session_state.auth_mode = "login"
            st.rerun()

    if not st.session_state.user:
        login_view()
        return

    if st.session_state.user.get("must_change_password"):
        change_password_view()
        return

    role = st.session_state.user.get("role")
    if role == "owner":
        owner_dashboard()
    elif role == "client":
        client_dashboard()
    elif role == "staff":
        staff_dashboard()

if __name__ == "__main__":
    main()