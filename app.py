import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score
# =========================================================
# PAGE CONFIGURATION
# =========================================================
st.set_page_config(
          page_title="Student Performance Dashboard",
          page_icon="🎓",
          layout="wide"
)
# =========================================================
# CUSTOM DESIGN
# =========================================================
st.markdown("""
<style>
.stApp {
          background-color: #f4f7fb;
}
.dashboard-header {
          background: linear-gradient(135deg, #173f5f, #20639b);
          padding: 30px;
          border-radius: 18px;
          text-align: center;
          margin-bottom: 25px;
}
.dashboard-header h1 {
          color: white;
          font-size: 36px;
          margin: 0;
}
.dashboard-header p {
          color: white;
          font-size: 17px;
}
div[data-testid="stMetric"] {
          background-color: white;
          padding: 20px;
          border-radius: 15px;
}
</style>
""", unsafe_allow_html=True)
# =========================================================
# MYSQL USER AUTHENTICATION
# =========================================================
import re
import hashlib
import hmac
import secrets
import mysql.connector
from mysql.connector import Error, IntegrityError
def get_db_connection():
    """Connect to the MySQL database using Streamlit secrets."""
    cfg = st.secrets["mysql"]
    return mysql.connector.connect(
        host=cfg["host"],
        port=int(cfg.get("port", 3306)),
        user=cfg["user"],
        password=cfg["password"],
        database=cfg["database"],
        connection_timeout=5,
    )
def create_users_table():
    """Create the user accounts table if it does not exist."""
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                full_name VARCHAR(100) NOT NULL,
                email VARCHAR(254) NULL UNIQUE,
                username VARCHAR(30) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        # Existing databases may have email marked NOT NULL; make it optional.
        cursor.execute("ALTER TABLE users MODIFY COLUMN email VARCHAR(254) NULL")

        # Add the admin flag to older databases without deleting existing users.
        cursor.execute("SHOW COLUMNS FROM users LIKE 'is_admin'")
        if cursor.fetchone() is None:
            cursor.execute(
                "ALTER TABLE users ADD COLUMN is_admin TINYINT(1) NOT NULL DEFAULT 0"
            )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS login_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NULL,
                username VARCHAR(30) NOT NULL,
                login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                login_role VARCHAR(20) NOT NULL,
                INDEX (user_id)
            )
            """
        )
        connection.commit()
    finally:
        cursor.close()
        connection.close()
def hash_password(password):
    """Return a PBKDF2 hash with a random per-user salt."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 600_000
    )
    return f"{salt.hex()}${digest.hex()}"
def verify_password(password, stored_hash):
    """Verify a password against the stored salt and hash."""
    try:
        salt_hex, digest_hex = stored_hash.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, 600_000
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False
def validate_registration(full_name, username, password, confirm_password):
    full_name = full_name.strip()
    username = username.strip()
    if not full_name or len(full_name) > 100:
        return "Enter a full name (maximum 100 characters)."
    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
        return "Username must be 3–30 characters using letters, numbers, or underscores."
    if len(password) < 8 or len(password) > 128:
        return "Password must be between 8 and 128 characters."
    if password != confirm_password:
        return "Passwords do not match."
    return None


def register_user(full_name, username, password):
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO users (full_name, email, username, password_hash) VALUES (%s, NULL, %s, %s)",
            (full_name.strip(), username.strip(), hash_password(password)),
        )
        connection.commit()
        return "success"
    except IntegrityError:
        if connection is not None and connection.is_connected():
            connection.rollback()
        return "duplicate"
    except Error:
        if connection is not None and connection.is_connected():
            connection.rollback()
        return "database_error"
    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None and connection.is_connected():
            connection.close()

def authenticate_user(username, password):
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            "SELECT id, full_name, password_hash, is_admin FROM users WHERE username = %s",
            (username.strip(),),
        )
        row = cursor.fetchone()
        if row and verify_password(password, row[2]):
            role = "admin" if bool(row[3]) else "user"
            cursor.execute(
                "INSERT INTO login_history (user_id, username, login_role) VALUES (%s, %s, %s)",
                (row[0], username.strip(), role),
            )
            connection.commit()
            return {"id": row[0], "full_name": row[1], "is_admin": bool(row[3])}
        return None
    except Error:
        return "database_error"
    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None and connection.is_connected():
            connection.close()
# =========================================================
# LOGIN, REGISTRATION AND ADMIN LOGIN
# =========================================================

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user_full_name" not in st.session_state:
    st.session_state.user_full_name = ""
if "is_admin" not in st.session_state:
    st.session_state.is_admin = False

if not st.session_state.logged_in:
    st.markdown("""
    <div class="dashboard-header">
        <h1>🎓 EduTrack AI — Student Performance System</h1>
        <p>Performance Analysis & Dropout Risk Prediction</p>
    </div>
    """, unsafe_allow_html=True)

    try:
        create_users_table()
    except Exception as exc:
        st.error(
            "Cannot connect to MySQL. Check that MySQL is running and "
            "that .streamlit/secrets.toml has the correct credentials."
        )
        st.stop()

    login_tab, register_tab, admin_tab = st.tabs([
        "🔐 User Login", "📝 New User Registration", "🛡️ Admin Login"
    ])

    with login_tab:
        st.subheader("🔐 Login to your account")
        with st.form("login_form"):
            login_username = st.text_input("Username", key="login_username")
            login_password = st.text_input("Password", type="password", key="login_password")
            login_submitted = st.form_submit_button("Login", use_container_width=True)
        if login_submitted:
            if not login_username.strip() or not login_password:
                st.error("Enter both username and password.")
            else:
                user = authenticate_user(login_username, login_password)
                if user == "database_error":
                    st.error("Database error. Please check your MySQL connection.")
                elif user and user.get("is_admin"):
                    st.session_state.logged_in = True
                    st.session_state.user_full_name = user["full_name"]
                    st.session_state.is_admin = True
                    st.success("Admin login successful!")
                    st.rerun()
                elif user:
                    st.session_state.logged_in = True
                    st.session_state.user_full_name = user["full_name"]
                    st.session_state.is_admin = False
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.error("Invalid username or password.")

    with register_tab:
        st.subheader("📝 Create a new account")
        with st.form("registration_form"):
            full_name = st.text_input("Full Name", max_chars=100)
            new_username = st.text_input("Username", max_chars=30)
            new_password = st.text_input("Password (minimum 8 characters)", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            register_submitted = st.form_submit_button("Register", use_container_width=True)
        if register_submitted:
            validation_error = validate_registration(
                full_name, new_username, new_password, confirm_password
            )
            if validation_error:
                st.error(validation_error)
            else:
                result = register_user(full_name, new_username, new_password)
                if result == "success":
                    st.success("Registration successful! Open User Login to sign in.")
                elif result == "duplicate":
                    st.error("That username is already registered. Please choose another username.")
                else:
                    st.error("Registration failed. Check your MySQL connection.")

    with admin_tab:
        st.subheader("🛡️ Administrator Login")
        st.caption("Only accounts marked as administrators can access admin records.")
        with st.form("admin_login_form"):
            admin_username = st.text_input("Admin username", key="admin_username")
            admin_password = st.text_input("Admin password", type="password", key="admin_password")
            admin_submitted = st.form_submit_button("Admin Login", use_container_width=True)
        if admin_submitted:
            if not admin_username.strip() or not admin_password:
                st.error("Enter both admin username and password.")
            else:
                admin_user = authenticate_user(admin_username, admin_password)
                if admin_user == "database_error":
                    st.error("Database error. Please check your MySQL connection.")
                elif admin_user and admin_user.get("is_admin"):
                    st.session_state.logged_in = True
                    st.session_state.user_full_name = admin_user["full_name"]
                    st.session_state.is_admin = True
                    st.success("Admin login successful!")
                    st.rerun()
                elif admin_user:
                    st.error("This account does not have administrator permission.")
                else:
                    st.error("Invalid admin username or password.")

    st.stop()

# Admin-only page: display registered accounts and successful login history.
if st.session_state.get("is_admin", False):
    st.markdown("""
    <div class="dashboard-header">
        <h1>🛡️ EduTrack AI Admin Panel</h1>
        <p>Registered users and successful login history</p>
    </div>
    """, unsafe_allow_html=True)
    try:
        connection = get_db_connection()
        users_df = pd.read_sql(
            "SELECT id, full_name, email, username, is_admin, created_at FROM users ORDER BY created_at DESC",
            connection,
        )
        history_df = pd.read_sql(
            "SELECT username, login_role, login_time FROM login_history ORDER BY login_time DESC",
            connection,
        )
        connection.close()
        st.subheader("👥 Registered Users")
        st.dataframe(users_df, use_container_width=True)
        st.subheader("🕒 Successful Login History")
        st.dataframe(history_df, use_container_width=True)
        st.download_button(
            "Download Login History CSV",
            history_df.to_csv(index=False),
            "login_history.csv",
            "text/csv",
        )
    except Exception:
        st.error("Could not load admin records. Check the MySQL connection and table setup.")
    if st.sidebar.button("🚪 Logout"):
        st.session_state.logged_in = False
        st.session_state.user_full_name = ""
        st.session_state.is_admin = False
        st.rerun()
    st.stop()

# =========================================================
# LOAD DATASET
# =========================================================
try:
          data = pd.read_csv(
                    "student_dropout_dataset.csv"
          )
except FileNotFoundError:
          st.error(
                    "Dataset file not found. "
                    "Keep student_dropout_dataset.csv "
                    "in the same folder as app.py."
          )
          st.stop()
# =========================================================
# DASHBOARD HEADER
# =========================================================
st.markdown("""
<div class="dashboard-header">
          <h1>🎓 Student Performance Dashboard</h1>
          <p>Student Performance & Dropout Risk Analysis</p>
</div>
""", unsafe_allow_html=True)
# =========================================================
# SIDEBAR
# =========================================================
st.sidebar.caption(f"Signed in as: {st.session_state.get('user_full_name', 'User')}")
st.sidebar.title("🎛️ Dashboard Filters")
gender_filter = st.sidebar.selectbox(
          "Gender",
          ["All"] + list(
                    data["Gender"].dropna().unique()
          )
)
attendance_range = st.sidebar.slider(
          "Attendance",
          0,
          100,
          (0, 100)
)
backlog_filter = st.sidebar.selectbox(
          "Backlogs",
          ["All"] +
          sorted(
                    data["Backlogs"].dropna().unique().tolist()
          )
)
gpa_range = st.sidebar.slider(
          "Previous GPA",
          0.0,
          10.0,
          (0.0, 10.0)
)
# =========================================================
# APPLY FILTERS
# =========================================================
filtered_data = data.copy()
if gender_filter != "All":
          filtered_data = filtered_data[
                    filtered_data["Gender"] == gender_filter
          ]
filtered_data = filtered_data[
          (filtered_data["Attendance"] >= attendance_range[0]) &
          (filtered_data["Attendance"] <= attendance_range[1])
]
if backlog_filter != "All":
          filtered_data = filtered_data[
                    filtered_data["Backlogs"] == backlog_filter
          ]
filtered_data = filtered_data[
          (filtered_data["Previous_GPA"] >= gpa_range[0]) &
          (filtered_data["Previous_GPA"] <= gpa_range[1])
]
# =========================================================
# KPI CARDS
# =========================================================
total_students = len(filtered_data)
risk_students = len(
          filtered_data[
                    filtered_data["Dropout"] == "Yes"
          ]
)
safe_students = len(
          filtered_data[
                    filtered_data["Dropout"] == "No"
          ]
)
if len(filtered_data) > 0:
          avg_attendance = round(
                    filtered_data["Attendance"].mean(),
                    2
          )
else:
          avg_attendance = 0
st.subheader("📊 Overview")
col1, col2, col3, col4 = st.columns(4)
col1.metric(
          "📚 Total Students",
          total_students
)
col2.metric(
          "⚠️ At Risk",
          risk_students
)
col3.metric(
          "✅ Safe Students",
          safe_students
)
col4.metric(
          "📊 Avg Attendance",
          f"{avg_attendance}%"
)
st.divider()
# =========================================================
# ML MODEL TRAINING
# =========================================================
st.subheader("🤖 Machine Learning Model")
# Required ML features
ml_features = [
          "Attendance",
          "Internal_Marks",
          "Backlogs",
          "Previous_GPA"
]
missing_features = [
          col for col in ml_features
          if col not in data.columns
]
if missing_features:
          st.error(
                    "Missing ML columns: "
                    + ", ".join(missing_features)
          )
          st.stop()
# Prepare X and y
X = data[ml_features].copy()
y = data["Dropout"].copy()
# Convert target Yes/No into 1/0
target_encoder = LabelEncoder()
y_encoded = target_encoder.fit_transform(y)
# Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(
          X,
          y_encoded,
          test_size=0.20,
          random_state=42,
          stratify=y_encoded
)
# Random Forest Model
model = RandomForestClassifier(
          n_estimators=100,
          random_state=42
)
model.fit(
          X_train,
          y_train
)
# Model Accuracy
y_pred = model.predict(X_test)
accuracy = accuracy_score(
          y_test,
          y_pred
)
st.success(
          f"🤖 Random Forest Model Accuracy: {accuracy * 100:.2f}%"
)
# =========================================================
# STUDENT SEARCH
# =========================================================
st.subheader("🔍 Search Student")
student_id = st.text_input(
          "Enter Student ID",
          placeholder="Example: STU00001"
)
if student_id:
          student = data[
                    data["Student_ID"].astype(str)
                    == str(student_id)
          ]
          if not student.empty:
                    st.subheader("👨‍🎓 Student Details")
                    st.dataframe(
                              student,
                              use_container_width=True
                    )
                    # ---------------------------------------------
                    # STUDENT VALUES
                    # ---------------------------------------------
                    attendance = float(
                              student["Attendance"].values[0]
                    )
                    marks = float(
                              student["Internal_Marks"].values[0]
                    )
                    backlogs = int(
                              student["Backlogs"].values[0]
                    )
                    gpa = float(
                              student["Previous_GPA"].values[0]
                    )
                    actual_status = student[
                              "Dropout"
                    ].values[0]
                    # ---------------------------------------------
                    # ML PREDICTION
                    # ---------------------------------------------
                    student_input = pd.DataFrame(
                              [[
                                        attendance,
                                        marks,
                                        backlogs,
                                        gpa
                              ]],
                              columns=ml_features
                    )
                    prediction = model.predict(
                              student_input
                    )[0]
                    prediction_probability = model.predict_proba(
                              student_input
                    )[0]
                    predicted_label = target_encoder.inverse_transform(
                              [prediction]
                    )[0]
                    confidence = max(
                              prediction_probability
                    ) * 100
                    # ---------------------------------------------
                    # PREDICTION RESULT
                    # ---------------------------------------------
                    st.subheader(
                              "🎯 ML Dropout Risk Prediction"
                    )
                    if predicted_label == "Yes":
                              st.error(
                                        f"🔴 HIGH DROPOUT RISK\n\n"
                                        f"Prediction Confidence: {confidence:.2f}%"
                              )
                    else:
                              st.success(
                                        f"🟢 LOW DROPOUT RISK\n\n"
                                        f"Prediction Confidence: {confidence:.2f}%"
                              )
                    # ---------------------------------------------
                    # STUDENT METRICS
                    # ---------------------------------------------
                    col1, col2, col3, col4 = st.columns(4)
                    col1.metric(
                              "Attendance",
                              f"{attendance}%"
                    )
                    col2.metric(
                              "Internal Marks",
                              marks
                    )
                    col3.metric(
                              "Backlogs",
                              backlogs
                    )
                    col4.metric(
                              "Previous GPA",
                              gpa
                    )
                    # ---------------------------------------------
                    # ACTUAL VS ML PREDICTION
                    # ---------------------------------------------
                    st.subheader(
                              "📌 Actual vs ML Prediction"
                    )
                    result_col1, result_col2 = st.columns(2)
                    with result_col1:
                              st.info(
                                        f"Dataset Status: {actual_status}"
                              )
                    with result_col2:
                              if predicted_label == "Yes":
                                        st.error(
                                                  f"ML Prediction: {predicted_label}"
                                        )
                              else:
                                        st.success(
                                                  f"ML Prediction: {predicted_label}"
                                        )
                    # ---------------------------------------------
                    # RISK REASONS
                    # ---------------------------------------------
                    st.subheader(
                              "⚠️ Risk Factors"
                    )
                    reasons = []
                    if attendance < 60:
                              reasons.append(
                                        "Low Attendance"
                              )
                    if marks < 40:
                              reasons.append(
                                        "Low Internal Marks"
                              )
                    if backlogs >= 3:
                              reasons.append(
                                        "Multiple Backlogs"
                              )
                    if gpa < 5:
                              reasons.append(
                                        "Low Previous GPA"
                              )
                    if reasons:
                              for reason in reasons:
                                        st.warning(
                                                  "• " + reason
                                        )
                    else:
                              st.success(
                                        "No major risk factors found."
                              )
                    # ---------------------------------------------
                    # SUGGESTIONS
                    # ---------------------------------------------
                    st.subheader(
                              "💡 Improvement Suggestions"
                    )
                    suggestions = []
                    if attendance < 75:
                              suggestions.append(
                                        "Increase attendance to at least 75%."
                              )
                    if marks < 60:
                              suggestions.append(
                                        "Improve internal marks above 60."
                              )
                    if backlogs > 0:
                              suggestions.append(
                                        "Clear existing backlogs."
                              )
                    if gpa < 6:
                              suggestions.append(
                                        "Improve overall academic performance."
                              )
                    if suggestions:
                              for suggestion in suggestions:
                                        st.info(
                                                  "• " + suggestion
                                        )
                    else:
                              st.success(
                                        "Student is performing strongly."
                              )
                    # ---------------------------------------------
                    # WHAT IF SIMULATION
                    # ---------------------------------------------
                    st.subheader(
                              "🔄 What-if ML Prediction"
                    )
                    new_attendance = st.slider(
                              "Attendance",
                              0,
                              100,
                              int(attendance)
                    )
                    new_marks = st.slider(
                              "Internal Marks",
                              0,
                              100,
                              int(marks)
                    )
                    new_backlogs = st.slider(
                              "Backlogs",
                              0,
                              6,
                              int(backlogs)
                    )
                    new_gpa = st.slider(
                              "Previous GPA",
                              0.0,
                              10.0,
                              float(gpa)
                    )
                    what_if_input = pd.DataFrame(
                              [[
                                        new_attendance,
                                        new_marks,
                                        new_backlogs,
                                        new_gpa
                              ]],
                              columns=ml_features
                    )
                    what_if_prediction = model.predict(
                              what_if_input
                    )[0]
                    what_if_label = target_encoder.inverse_transform(
                              [what_if_prediction]
                    )[0]
                    if what_if_label == "Yes":
                              st.error(
                                        "🔴 Student may remain at HIGH dropout risk."
                              )
                    else:
                              st.success(
                                        "🟢 Student is predicted to be LOW dropout risk."
                              )
                    # ---------------------------------------------
                    # DOWNLOAD REPORT
                    # ---------------------------------------------
                    st.subheader(
                              "📥 Student Report"
                    )
                    report = student.copy()
                    report["ML_Prediction"] = predicted_label
                    report["ML_Confidence"] = round(
                              confidence,
                              2
                    )
                    report_csv = report.to_csv(
                              index=False
                    )
                    st.download_button(
                              "Download Student ML Report",
                              report_csv,
                              f"{student_id}_ML_report.csv",
                              "text/csv"
                    )
          else:
                    st.warning(
                              "⚠️ Student ID not found."
                    )
st.divider()
# =========================================================
# PERFORMANCE ANALYSIS
# =========================================================
st.subheader(
          "📈 Performance Analysis"
)
col1, col2 = st.columns(2)
sns.set_style(
          "whitegrid"
)
# =========================================================
# DROPOUT DISTRIBUTION
# =========================================================
with col1:
          st.write(
                    "### Dropout Distribution"
          )
          if not filtered_data.empty:
                    fig1, ax1 = plt.subplots()
                    filtered_data[
                              "Dropout"
                    ].value_counts().plot(
                              kind="pie",
                              autopct="%1.1f%%",
                              ax=ax1
                    )
                    ax1.set_ylabel("")
                    st.pyplot(fig1)
                    plt.close(fig1)
# =========================================================
# ATTENDANCE VS DROPOUT
# =========================================================
with col2:
          st.write(
                    "### Attendance vs Dropout"
          )
          if not filtered_data.empty:
                    fig2, ax2 = plt.subplots()
                    sns.boxplot(
                              x="Dropout",
                              y="Attendance",
                              data=filtered_data,
                              ax=ax2
                    )
                    st.pyplot(fig2)
                    plt.close(fig2)
# =========================================================
# BACKLOGS VS DROPOUT
# =========================================================
st.write(
          "### 📚 Backlogs vs Dropout"
)
if not filtered_data.empty:
          fig3, ax3 = plt.subplots()
          sns.countplot(
                    x="Backlogs",
                    hue="Dropout",
                    data=filtered_data,
                    ax=ax3
          )
          st.pyplot(fig3)
          plt.close(fig3)
st.divider()
# =========================================================
# TOP PERFORMING STUDENTS
# =========================================================
st.subheader(
          "🏆 Top Performing Students"
)
if not filtered_data.empty:
          top_students = filtered_data.sort_values(
                    by="Previous_GPA",
                    ascending=False
          ).head(5)
          st.dataframe(
                    top_students[
                              [
                                        "Student_ID",
                                        "Previous_GPA",
                                        "Attendance",
                                        "Internal_Marks"
                              ]
                    ],
                    use_container_width=True
          )
st.divider()
# =========================================================
# DATASET PREVIEW
# =========================================================
st.subheader(
          "📋 Dataset Preview"
)
st.dataframe(
          filtered_data,
          use_container_width=True
)
# =========================================================
# DOWNLOAD DATA
# =========================================================
st.subheader(
          "📥 Download Data"
)
st.download_button(
          "Download Current Dataset",
          filtered_data.to_csv(index=False),
          "student_data.csv",
          "text/csv"
)
# =========================================================
# LOGOUT
# =========================================================
st.sidebar.divider()
if st.sidebar.button(
          "🚪 Logout"
):
          st.session_state.logged_in = False
          st.session_state.user_full_name = ""
          st.rerun()
