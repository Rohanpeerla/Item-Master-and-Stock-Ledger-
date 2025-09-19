from flask_apscheduler import APScheduler
from datetime import datetime, timedelta
items = []
packages_list = []
from PIL import Image, ImageDraw, ImageFont
import random
import re
from io import BytesIO
from flask import send_file, session
from flask_login import current_user, login_required
from flask import render_template, request
from functools import wraps
from flask import abort
from flask import Flask, jsonify,render_template, request, redirect, url_for, session, flash,send_from_directory,send_file
import mysql.connector
from functools import wraps
import random
import string
from werkzeug.security import generate_password_hash, check_password_hash
import json
from datetime import date
from datetime import datetime, timedelta
import mysql.connector
db = mysql.connector.connect(
      host='localhost',
        user='root',
        password='Rohan@1225',
        database='item'
)
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with environment var or config in production!

# In-memory token store for password reset (use DB or persistent storage in production)
reset_tokens = {}

def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='Rohan@1225',
        database='item'
    )

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        connection = get_db_connection()
        cursor = connection.cursor(buffered=True)
        cursor.execute('SELECT username FROM user_master WHERE email = %s', (email,))
        user = cursor.fetchone()
        cursor.close()
        connection.close()

        if user:
            reset_token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))  # longer token
            reset_tokens[reset_token] = user[0]
            flash(f'Password reset link: {url_for("reset_password", token=reset_token, _external=True)}', 'info')
            return redirect(url_for('login'))
        else:
            flash('No account found with that email address', 'danger')
            return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    username = reset_tokens.get(token)
    if not username:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        if not new_password or len(new_password) < 6:
            flash('Password must be at least 6 characters long.', 'warning')
            return redirect(request.url)

        hashed_password = generate_password_hash(new_password)

        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute('UPDATE user_master SET password = %s WHERE username = %s', (hashed_password, username))
        connection.commit()
        cursor.close()
        connection.close()

        reset_tokens.pop(token)
        flash('Password has been updated successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')

        connection = get_db_connection()
        cursor = connection.cursor(buffered=True)
        cursor.execute('SELECT password FROM user_master WHERE username = %s', (session['username'],))
        db_password = cursor.fetchone()

        if db_password and check_password_hash(db_password[0], current_password):
            if not new_password or len(new_password) < 6:
                flash('New password must be at least 6 characters.', 'warning')
                cursor.close()
                connection.close()
                return redirect(url_for('change_password'))

            hashed_password = generate_password_hash(new_password)
            cursor.execute('UPDATE user_master SET password = %s WHERE username = %s',
                           (hashed_password, session['username']))
            connection.commit()
            flash('Password updated successfully!', 'success')
        else:
            flash('Current password is incorrect', 'danger')

        cursor.close()
        connection.close()
        return redirect(url_for('change_password'))

    return render_template('change_password.html')

@app.route('/')
@login_required
def index():
    connection = get_db_connection()
    cursor = connection.cursor(buffered=True)
    cursor.execute('''
        SELECT im.itemid, im.itemname, im.totalqty, im.totalprice,
               idm.itemqty, idm.itemprice, idm.total
        FROM item_master im
        JOIN item_details_master idm ON im.itemid = idm.itemid
    ''')
    data = cursor.fetchall()
    cursor.close()
    connection.close()
    return render_template('index.html', data=data)

@app.route('/add', methods=['POST'])
@login_required
def add_item():
    itemname = request.form.get('itemname')
    totalqty = request.form.get('totalqty')
    totalprice = request.form.get('totalprice')
    itemqty = request.form.get('itemqty')
    itemprice = request.form.get('itemprice')

    if not all([itemname, totalqty, totalprice, itemqty, itemprice]):
        flash('All fields are required.', 'warning')
        return redirect(url_for('index'))

    today = date.today()

    connection = get_db_connection()
    cursor = connection.cursor(buffered=True)

    cursor.execute('''
        INSERT INTO item_master (itemname, totalqty, totalprice, purchasedate)
        VALUES (%s, %s, %s, %s)
    ''', (itemname, totalqty, totalprice, today))
    connection.commit()

    itemid = cursor.lastrowid

    cursor.execute('''
        INSERT INTO item_details_master (itemid, itemqty, itemprice)
        VALUES (%s, %s, %s)
    ''', (itemid, itemqty, itemprice))
    connection.commit()

    cursor.close()
    connection.close()
    flash('Item added successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/delete/<int:itemid>', methods=['GET'])
@login_required
def delete_item(itemid):
    connection = get_db_connection()
    cursor = connection.cursor(buffered=True)
    cursor.execute('DELETE FROM item_details_master WHERE itemid = %s', (itemid,))
    cursor.execute('DELETE FROM item_master WHERE itemid = %s', (itemid,))
    connection.commit()
    cursor.close()
    connection.close()
    flash('Item deleted successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session or 'role' not in session:
        return redirect('/login')

    username = session.get('username')
    role = session.get('role')

    # Example data — customize this based on role if needed
    bills_per_month = {'January': 1, 'February': 1, 'March': 1, 'April': 1, 'May': 1}
    items_sold = {'TV': 2, 'Mobile': 1, 'Fridge': 1, 'Laptop': 2, 'Tablet': 1, 'Washing Machine': 1}
    current_date = datetime.now().strftime("%d-%m-%Y")

    return render_template('dashboard.html',
                           username=username,
                           role=role,
                           bills_labels=list(bills_per_month.keys()),
                           bills_data=list(bills_per_month.values()),
                           items_labels=list(items_sold.keys()),
                           items_data=list(items_sold.values()),
                           current_date=current_date)


@app.route('/dashboard/data')
def dashboard_data():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 1. Overall stock ledger cost
    cursor.execute("SELECT SUM(stock_cost) AS total_cost FROM StockLedger")
    total_stock_cost = cursor.fetchone()['total_cost'] or 0

    # 2. Number of bills made (all time)
    cursor.execute("SELECT COUNT(*) AS bill_count FROM Bills")
    bill_count = cursor.fetchone()['bill_count'] or 0

    # 3. Total cost of bills per day (today)
    today_str = datetime.now().strftime('%Y-%m-%d')
    cursor.execute("SELECT SUM(total_amount) AS daily_cost FROM Bills WHERE DATE(bill_date) = %s", (today_str,))
    daily_cost = cursor.fetchone()['daily_cost'] or 0

    # 4. Total items (sum of quantities in StockLedger)
    cursor.execute("SELECT SUM(quantity) AS total_items FROM StockLedger")
    total_items = cursor.fetchone()['total_items'] or 0

    # Chart 1: Bills per month for the last 12 months
    cursor.execute("""
        SELECT DATE_FORMAT(bill_date, '%Y-%m') AS month, COUNT(*) AS bill_count 
        FROM Bills 
        WHERE bill_date >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
        GROUP BY month
        ORDER BY month
    """)
    bills_per_month = cursor.fetchall()

       # Chart 2: Items sold per month (from BillItems or similar)
    cursor.execute("""
        SELECT DATE_FORMAT(bill_date, '%Y-%m') AS month, SUM(quantity) AS items_sold
        FROM BillItems bi
        JOIN Bills b ON bi.bill_id = b.id
        WHERE bill_date >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
        GROUP BY month
        ORDER BY month
    """)
    items_sold_result = cursor.fetchall()

    cursor.close()
    conn.close()

    # Format data for JSON
    bills_months = [row['month'] for row in bills_per_month]
    bills_counts = [row['bill_count'] for row in bills_per_month]

    items_months = [row['month'] for row in items_sold_result]
    items_counts = [row['items_sold'] for row in items_sold_result]

    return jsonify({
        'total_stock_cost': total_stock_cost,
        'bill_count': bill_count,
        'daily_cost': daily_cost,
        'total_items': total_items,
        'bills_per_month': {
            'labels': bills_months,
            'data': bills_counts
        },
        'items_sold': {
            'labels': items_months,
            'data': items_counts
        }
    })

@app.route('/update/<int:itemid>', methods=['GET', 'POST'])
@login_required
def update_item(itemid):
    # ✅ Restrict write access to item-dashboard for managers
    allowed = any(menu['url'] == '/item-dashboard' and menu['can_write'] for menu in session.get('menus', []))
    if not allowed:
        return "Access Denied", 403


    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    if request.method == 'POST':
        itemname = request.form.get('itemname')
        totalqty = request.form.get('totalqty')
        totalprice = request.form.get('totalprice')
        itemqty = request.form.get('itemqty')
        itemprice = request.form.get('itemprice')

        cursor.execute('''
            UPDATE item_master SET itemname=%s, totalqty=%s, totalprice=%s
            WHERE itemid=%s
        ''', (itemname, totalqty, totalprice, itemid))
        
        cursor.execute('''
            UPDATE item_details_master SET itemqty=%s, itemprice=%s
            WHERE itemid=%s
        ''', (itemqty, itemprice, itemid))

        connection.commit()
        cursor.close()
        connection.close()
        flash('Item updated successfully!', 'success')
        return redirect(url_for('index'))

    cursor.execute('''
        SELECT im.itemid, im.itemname, im.totalqty, im.totalprice,
               idm.itemqty, idm.itemprice
        FROM item_master im
        JOIN item_details_master idm ON im.itemid = idm.itemid
        WHERE im.itemid = %s
    ''', (itemid,))
    item = cursor.fetchone()
    cursor.close()
    connection.close()
    return render_template('update_item.html', item=item)

@app.route('/purchase_order_form')
@login_required
def purchase_order_form():
    return render_template('purchase_order_form.html')

@app.route('/purchase_order_list')
@login_required
def purchase_order_list():
    return render_template('purchase_order_list.html', orders=orders)


orders = [
    {
        "id": 1,
        "supplier_name": "Jai Balaji Suppliers",
        "order_date": "2025-05-21",
        "total_amount": 150000,
        "items": [
            {"item_name": "One Plus Nord Ce 2 Lite 5g", "quantity": 1, "rate": 20000.00, "amount": 20000.00},
            {"item_name": "Samsung 8k Tv", "quantity": 1, "rate": 50000.00, "amount": 50000.00}
        ]
    },
    {
        "id": 2,
        "supplier_name": "Supplier B",
        "order_date": "2025-05-20",
        "total_amount": 100000,
        "items": [
            {"item_name": "Lenovo Idea pad 3", "quantity": 1, "rate": 40000.00, "amount": 40000.00}
        ]
    }
]

orders = [
    {
        "id": 1,
        "supplier_name": "Supplier A",
        "order_date": "2025-05-21",
        "total_amount": 100000,
        "items": [
            {"item_name": "One Plus Nord Ce 2 Lite 5g", "quantity": 1, "rate": 20000, "amount": 20000},
            {"item_name": "Samsung 8k Tv", "quantity": 1, "rate": 50000, "amount": 50000},
        ],
    },
    {
        "id": 2,
        "supplier_name": "Supplier B",
        "order_date": "2025-05-20",
        "total_amount": 150000,
        "items": [
            {"item_name": "Lenovo Idea pad 3", "quantity": 1, "rate": 40000, "amount": 40000},
        ],
    },
]

@app.route('/api/orders')
def get_orders():
    orders = [
        {
            "id": 1,
            "supplier_name": "Supplier A",
            "order_date": "2025-05-21",
            "total_amount": 100000,
            "items": [
                {"item_name": "One Plus Nord Ce 2 Lite 5g", "quantity": 1, "rate": 20000, "amount": 20000},
                {"item_name": "Samsung 8k Tv", "quantity": 3, "rate": 50000, "amount": 150000},
            ],
        },
        {
            "id": 2,
            "supplier_name": "Supplier B",
            "order_date": "2025-05-20",
            "total_amount": 120000,
            "items": [
                {"item_name": "LG 1.5 Ton AC", "quantity": 6, "rate": 30000, "amount": 180000}
            ]
        }
    ]
    return jsonify(orders)

@app.route('/new-order')
def new_order():
    return render_template('new_order.html')

@app.route('/items')
def get_items():
    # Example static data for now; ideally replace with DB query
    items_list = [
        {"name": "One Plus Nord Ce 2 Lite 5g", "quantity": 1, "price": 20000.00, "reorder_level": 5, "total_amount": 20000.00},
        {"name": "Samsung 8k Tv", "quantity": 1, "price": 50000.00, "reorder_level": 3, "total_amount": 50000.00},
        {"name": "Lenovo Idea pad 3", "quantity": 1, "price": 40000.00, "reorder_level": 7, "total_amount": 40000.00},
        {"name": "Samsung Washing Machine (Front load)", "quantity": 1, "price": 35000.00, "reorder_level": 2, "total_amount": 35000.00},
        {"name": "LG Refrigerator 250L", "quantity": 1, "price": 30000.00, "reorder_level": 4, "total_amount": 30000.00}
    ]
    return render_template('items.html', items=items_list)

@app.route('/purchase_order/<int:order_id>')
@login_required
def view_purchase_order(order_id):
    order = next((o for o in orders if o['id'] == order_id), None)
    if not order:
        return "Purchase Order not found", 404
    return render_template('purchase_order_detail.html', order=order)

def get_bill_data():
    connection = mysql.connector.connect(
        host='localhost',
        user='root',
        password='Rohan@1225',
        database='item'
    )
    cursor = connection.cursor(dictionary=True)
    query = """
        SELECT
            b.BillID,
            b.BillDate,
            b.TotalAmount,
            b.NumberOfItems,
            i.ItemName,
            bi.Quantity,
            bi.Rate,
            bi.Amount
        FROM Bills b
        JOIN BillItems bi ON b.BillID = bi.BillID
        JOIN ItemMaster i ON bi.ItemID = i.ItemID
        ORDER BY b.BillID DESC
    """
    cursor.execute(query)
    data = cursor.fetchall()
    cursor.close()
    connection.close()
    return data

@app.route('/stock_ledger')
def stock_ledger():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Query to get all items with current quantity and expiry date
        query = """
            SELECT 
                sl.StockLedgerID AS StockLedgerNumber,
                im.itemName,
                SUM(CASE WHEN sl.ChangeType = 'IN' THEN sl.QuantityChange ELSE -sl.QuantityChange END) AS CurrentStock,
                MAX(sl.ItemExpiryDate) AS ExpiryDate
            FROM stockledgerhistory sl
            JOIN item_master im ON sl.StockLedgerID = im.ItemID
            GROUP BY sl.StockLedgerID, im.itemName;
        """
        cursor.execute(query)
        results = cursor.fetchall()

        # Prepare data for template
        stock_ledger = []
        for item in results:
            stock_ledger.append({
                "StockLedgerNumber": f"SL-{item['StockLedgerNumber']}",
                "itemName": item['itemName'],
                "openingBalance": 100,  # Assuming initial balance is 100
                "currentQty": item['CurrentStock'],
                "expiryDate": item['ExpiryDate']
            })

        return render_template('stock_ledger.html', stock_ledger=stock_ledger)

    finally:
        cursor.close()
        conn.close()

@app.route('/get_role_menu')
@login_required
def get_role_menu():
    role = request.args.get('role')
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT menu_id, can_read, can_write, can_delete
        FROM role_menu_assignment
        WHERE role_id = %s
    """, (role,))
    rows = cursor.fetchall()
    cursor.close()
    connection.close()

    response = []
    for row in rows:
        response.append({
            'id': row['menu_id'],
            'checked': True,
            'rights': {
                'read': bool(row['can_read']),
                'write': bool(row['can_write']),
                'delete': bool(row['can_delete'])
            }
        })

    return jsonify(response)

@app.route('/assign_menus', methods=['GET', 'POST'])
def assign_menus():
    conn = mysql.connect()
    cursor = conn.cursor()

    if request.method == 'POST':
        # Handle assignment
        data = request.get_json()
        role_id = data['role_id']
        menu_ids = data['menu_ids']

        cursor.execute("DELETE FROM role_menu_assignment WHERE RoleID = %s", (role_id,))
        for menu_id in menu_ids:
            cursor.execute("INSERT INTO role_menu_assignment (RoleID, MenuID) VALUES (%s, %s)", (role_id, menu_id))

        conn.commit()
        return jsonify({'message': 'Menus assigned successfully'})

    # GET method – fetch roles and menus
    cursor.execute("SELECT RoleID, RoleName FROM role_master")
    roles = cursor.fetchall()

    cursor.execute("SELECT MenuID, MenuName, URL, ParentMenuID FROM menu_master")
    menus = cursor.fetchall()

    return render_template('assign_menus.html', roles=roles, menus=menus)

@app.route('/assign_role_menus')
def assign_role_menus():
    # Dummy data — replace with your actual DB queries
    roles = [
        {"role_id": 1, "role_name": "Admin"},
        {"role_id": 2, "role_name": "User"}
    ]

    menus = [
        {"menu_id": 1, "menu_name": "Dashboard", "parent_id": None},
        {"menu_id": 2, "menu_name": "Users", "parent_id": None},
        {"menu_id": 3, "menu_name": "Add User", "parent_id": 2},
        {"menu_id": 4, "menu_name": "Reports", "parent_id": None}
    ]

    return render_template('assign_role_menus.html', roles=roles, menus=menus)

@app.route('/save_role_menu', methods=['POST'])
def save_role_menu():
    data = request.json
    role = data.get('role')
    access = data.get('access')
    
    # Save this data to your database or process accordingly
    print(f"Saving access for role: {role}")
    print(access)

    return jsonify({"message": f"Access rights saved for role: {role}"})

def get_menu_tree():
    conn = mysql.connector.connect(user='root', password='yourpassword', database='yourdb')
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM MenuMaster")
    all_menus = cursor.fetchall()

    def build_tree(parent_id):
        return [
            {
                "menu_id": menu["MenuID"],
                "text": menu["MenuName"],
                "url": menu["URL"],
                "parent_menu_id": menu["ParentMenuID"],
                "children": build_tree(menu["MenuID"])
            }
            for menu in all_menus if menu["ParentMenuID"] == parent_id
        ]

    return build_tree(None)

    # Build menu tree
    def build_tree(parent_id):
        return [
            {
                "id": menu["MenuID"],
                "text": menu["MenuName"],
                "url": menu["URL"],
                "children": build_tree(menu["MenuID"])
            }
            for menu in all_menus if menu["ParentMenuID"] == parent_id
        ]

    return build_tree(None)

@app.route("/api/roles")
def get_roles():
    cursor = mysql.connection.cursor(dictionary=True)
    cursor.execute("SELECT RoleID, RoleName FROM role_master")
    roles = cursor.fetchall()
    return jsonify(roles)

@app.route("/api/menus")
def get_menus():
    cursor = mysql.connection.cursor(dictionary=True)
    cursor.execute("SELECT MenuID, MenuName, ParentMenuID FROM menu_master")
    menus = cursor.fetchall()
    return jsonify(menus)

def get_user_menus(role_id):
    cur = mysql.connection.cursor()
    query = '''
        SELECT m.menu_name, m.menu_url 
        FROM menu_master m
        JOIN role_menu_assignment rma ON m.menu_id = rma.menu_id
        WHERE rma.role_id = %s
    '''
    cur.execute(query, (role_id,))
    result = cur.fetchall()
    cur.close()
    return result

def get_all_menus_hierarchy():
    cur = mysql.connection.cursor()
    cur.execute("SELECT MenuID, MenuName, ParentID FROM menu_master WHERE IsActive=1")
    rows = cur.fetchall()
    cur.close()

    # Build a menu tree
    menu_dict = {row[0]: {'id': row[0], 'name': row[1], 'parent': row[2], 'children': []} for row in rows}
    root_menus = []

    for menu in menu_dict.values():
        if menu['parent'] is None:
            root_menus.append(menu)
        else:
            parent = menu_dict.get(menu['parent'])
            if parent:
                parent['children'].append(menu)

    return root_menus

@app.route('/reports')
def reports():
    role_id = session.get('role_id')
    if not role_id:
        return redirect('/login')

    if not check_menu_access(role_id, 'Reports'):
        return "Access Denied", 403

    return render_template('simple_page.html', title='Reports')

@app.route('/settings')
def settings():
    return render_template('simple_page.html', title='Settings')

@app.route('/profile')
def profile():
    return render_template('simple_page.html', title='Profile')

@app.route('/notifications')
def notifications():
    return render_template('simple_page.html', title='Notifications')

@app.route('/help')
def help():
    return render_template('simple_page.html', title='Help')

@app.route('/reports-overview')
def reports_overview():
    return render_template('simple_page.html', title='Reports Overview')

@app.route('/sales-report')
def sales_report():
    return render_template('simple_page.html', title='Sales Report')

@app.route('/inventory-report')
def inventory_report():
    return render_template('simple_page.html', title='Inventory Report')


@app.route('/audit-logs')
def audit_logs():
    return render_template('simple_page.html', title='Audit Logs')

@app.route('/system-status')
def system_status():
    return render_template('simple_page.html', title='System Status')

@app.route('/user-management')
def user_management():
    return render_template('simple_page.html', title='User Management')

@app.route('/item-master')
def item_master():
    if not session.get('username'):
        return redirect(url_for('login'))

    allowed = any(menu['url'] == '/item-master' and menu['can_read'] for menu in session.get('menus', []))
    if not allowed:
        return "Access Denied", 403

    # render item master page
    return render_template('item_master.html')

def get_sidebar_menus(role_id):
    cursor = mysql.connection.cursor(dictionary=True)
    cursor.execute("""
        SELECT mm.menu_name, mm.url, mm.parent_id
        FROM menu_master mm
        JOIN role_menu_assignment rma ON mm.menu_id = rma.menu_id
        WHERE rma.role_id = %s AND rma.can_read = 1
        ORDER BY mm.parent_id, mm.menu_id
    """, (role_id,))
    return cursor.fetchall()

@app.context_processor
def inject_sidebar_menus():
    role_id = session.get('role_id')
    if role_id:
        menus = get_sidebar_menus(role_id)
        return dict(sidebar_menus=menus)
    return dict(sidebar_menus=[])

def check_menu_access(role_id, menu_name):
    cursor = mysql.connection.cursor()
    query = '''
        SELECT 1 FROM role_menu_assignment rma
        JOIN menu_master mm ON rma.menu_id = mm.menu_id
        WHERE rma.role_id = %s AND mm.menu_name = %s AND rma.can_read = 1
    '''
    cursor.execute(query, (role_id, menu_name))
    result = cursor.fetchone()
    cursor.close()
    return result is not None

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] != required_role:
                abort(403)  # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/admin-dashboard')
def admin_dashboard():
    if 'username' not in session or session.get('role') != 'Admin':
        abort(403)
    return redirect(url_for('dashboard'))  # Or render a separate admin dashboard

@app.route('/manager-dashboard')
def manager_dashboard():
    print("Username:", session.get('username'))
    print("Role:", session.get('role'))

    if 'username' not in session or session.get('role') != 'Manager':
        abort(403)
    
    # Option 1: Show a custom dashboard for manager
    return render_template('dashboard.html', username=session['username'])

    # Option 2: Or just redirect to common dashboard
    # return redirect(url_for('dashboard'))


@app.route('/captcha')
def serve_captcha():
    captcha_text = str(random.randint(10000, 99999))  # Only numbers
    session['captcha'] = captcha_text

    img = Image.new('RGB', (120, 40), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)

    try:
        font = ImageFont.truetype("arial.ttf", 28)
    except:
        font = ImageFont.load_default()

    draw.text((10, 5), captcha_text, font=font, fill=(0, 0, 0))

    buf = BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

def build_menu_tree(menu_items):
    # Lowercase all keys for consistency
    normalized_items = [{k.lower(): v for k, v in item.items()} for item in menu_items]

    # Create a dictionary with MenuID as key
    menu_dict = {item['menuid']: dict(item, children=[]) for item in normalized_items}

    tree = []
    for item in normalized_items:
        parent_id = item['parentid']
        if parent_id and parent_id in menu_dict:
            menu_dict[parent_id]['children'].append(menu_dict[item['menuid']])
        else:
            tree.append(menu_dict[item['menuid']])
    return tree

@app.route('/api/get-username')
def get_username():
    username = session.get('username', None)
    return {'username': username}

@app.route('/report')
def report():
    if 'username' not in session:
        return redirect(url_for('login'))

    items = [
        {"name": "One Plus Nord Ce 2 Lite 5g", "units": 1, "unit_price": 20000.00, "quantity": 5, "rate": 20000.00, "total": 100000.00},
        {"name": "Samsung 8k Tv", "units": 1, "unit_price": 50000.00, "quantity": 3, "rate": 50000.00, "total": 150000.00},
        {"name": "Lenovo Idea pad 3", "units": 1, "unit_price": 40000.00, "quantity": 7, "rate": 40000.00, "total": 280000.00},
        {"name": "Samsung Washing Machine (Front load)", "units": 1, "unit_price": 30000.00, "quantity": 4, "rate": 30000.00, "total": 120000.00},
        {"name": "Blue Star 1.5 Ton Inverter Ac", "units": 1, "unit_price": 40000.00, "quantity": 2, "rate": 40000.00, "total": 80000.00},
        {"name": "LG 1.5 Ton AC", "units": 1, "unit_price": 30000.00, "quantity": 6, "rate": 30000.00, "total": 180000.00},
        {"name": "LG Smart TV AC", "units": 1, "unit_price": 30000.00, "quantity": 8, "rate": 30000.00, "total": 240000.00},
        {"name": "Apple iPhone 12, 256 GB, Cherry Red", "units": 1, "unit_price": 75000.00, "quantity": 1, "rate": 75000.00, "total": 75000.00},
        {"name": "Mouse", "units": 10, "unit_price": 10000.00, "quantity": 10, "rate": 10000.00, "total": 100000.00}
    ]

    return render_template("report.html", items=items)


@app.route('/user_roles')
def user_roles():
    users = [
        {"username": "manager", "roles": ["Manager", "Editor"]},
        {"username": "admin", "roles": ["Admin", "Superuser"]},
        {"username": "aniran", "roles": ["Viewer"]}
    ]
    return render_template('user_roles.html', users=users)


@app.route('/stock_ledger/edit/<int:ledger_id>', methods=['GET', 'POST'])
@login_required
def edit_stock_ledger(ledger_id):
    allowed = any(menu['url'] == '/stock_ledger' and menu.get('can_write') for menu in session.get('menus', []))
    if not allowed:
        return "Access Denied", 403

    # handle update logic
    return render_template('edit_stock_ledger.html')

@app.route('/contacts')
def contacts():
    return render_template('contacts.html')

@app.route('/item-groups')
def item_groups():
    return render_template('item_groups.html', username='Admin')  # Or dynamic username


@app.route('/sales-orders')
def sales_orders():
    return render_template('sales_orders.html')

@app.route('/packages')
def packages():
    return render_template('packages.html', packages=packages_list)


@app.route('/invoices')
def invoices():
    return render_template('invoices.html')

@app.route('/purchase-orders')
def purchase_orders():
    return render_template('purchase_order_list.html')

@app.route('/bills')
def bills():
    return render_template('bills.html')

@app.route('/integrations')
def integrations():
    return render_template('integrations.html')

from flask import send_from_directory


from flask import request, redirect
import re

@app.route('/add-item-group', methods=['POST'])
def add_item_group():
    group_name = request.form.get('group_name')
    description = request.form.get('description')
    mobile = request.form.get('mobile')
    email = request.form.get('email')
    qty = request.form.get('qty')
    gst_percent = request.form.get('gst_percent')

    # Check for missing inputs
    if not all([group_name, description, mobile, email, qty, gst_percent]):
        return "All fields are required", 400

    # Name must be only letters and spaces
    if not re.match(r'^[A-Za-z ]+$', group_name):
        return "Name must contain only letters", 400

    # Mobile must be exactly 10 digits
    if not re.match(r'^\d{10}$', mobile):
        return "Mobile number must be exactly 10 digits", 400

    # Email must be valid
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return "Invalid email address", 400

    # Quantity must be digits only
    if not qty.isdigit():
        return "Quantity must be numeric", 400

    # GST must be a number <= 100
    try:
        gst = float(gst_percent)
        if gst < 0 or gst > 100:
            return "GST percent must be between 0 and 100", 400
    except:
        return "Invalid GST percent", 400

    # ✅ All validations passed — insert into DB here if needed

    return redirect('/item-groups')

@app.route('/add-package', methods=['POST'])
def add_package():
    package_name = request.form.get('package_name')
    product_count = request.form.get('product_count')
    email = request.form.get('email')
    mobile = request.form.get('mobile')

    if not package_name or not product_count or not email or not mobile:
        return "All fields are required", 400

    # Append to in-memory list
    packages_list.append({
        'name': package_name,
        'count': product_count,
        'email': email,
        'mobile': mobile
    })

    return redirect('/packages')

@app.route('/add-product', methods=['POST'])
def add_product():
    name = request.form['name']
    units = request.form['units']
    unit_price = float(request.form['unit_price'])
    quantity = int(request.form['quantity'])
    rate = float(request.form['rate'])
    total = unit_price * quantity

    new_item = {
        'name': name,
        'units': units,
        'unit_price': unit_price,
        'quantity': quantity,
        'rate': rate,
        'total': total
    }
    items.append(new_item)

    return redirect('/report')  # ✅ Redirect to correct route

@app.route('/pipes-demo')
def pipes_demo():
    return render_template('pipes_demo.html')

from flask import jsonify, request
import mysql.connector
from datetime import datetime, timedelta

@app.route('/api/notifications')
def get_notifications():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    notifications = []

    try:
        # --- LOW STOCK ITEMS ---
        query_low_stock = """
        SELECT 
            im.ItemID,
            im.itemname AS itemName,
            SUM(CASE WHEN slh.ChangeType = 'IN' THEN slh.QuantityChange ELSE -slh.QuantityChange END) AS CurrentStock,
            im.minQty
        FROM stockledgerhistory slh
        JOIN billitems bi ON slh.BillID = bi.BillID
        JOIN item_master im ON bi.ItemID = im.ItemID
        GROUP BY bi.ItemID, im.itemname, im.minQty
        HAVING CurrentStock < im.minQty;
        """
        cursor.execute(query_low_stock)
        low_stock_items = cursor.fetchall()

        for item in low_stock_items:
            notifications.append({
                "message": f"Item {item['itemName']} has low stock.",
                "itemId": item['ItemID'],
                "stockLedgerNumber": f"SL-{item['ItemID']}"
            })

        # --- EXPIRING ITEMS (within next 7 days) ---
        seven_days_from_now = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d')

        query_expiring = """
        SELECT 
            bi.ItemID,
            im.itemname AS itemName,
            MIN(slh.ItemExpiryDate) AS NearestExpiryDate
        FROM stockledgerhistory slh
        JOIN billitems bi ON slh.BillID = bi.BillID
        JOIN item_master im ON bi.ItemID = im.ItemID
        WHERE slh.ItemExpiryDate IS NOT NULL
          AND slh.ChangeType = 'IN'
          AND slh.ItemExpiryDate <= %s
        GROUP BY bi.ItemID, im.itemname;
        """
        cursor.execute(query_expiring, (seven_days_from_now,))
        expiring_items = cursor.fetchall()

        for item in expiring_items:
            days_left = (item['NearestExpiryDate'] - datetime.now().date()).days
            notifications.append({
                "message": f"Item {item['itemName']} is nearing expiry (in {days_left} day(s)).",
                "itemId": item['ItemID'],
                "expiryDate": item['NearestExpiryDate'].strftime('%Y-%m-%d'),
                "stockLedgerNumber": f"SL-{item['ItemID']}"
            })

    finally:
        cursor.close()
        conn.close()

    return jsonify(notifications)

# Initialize scheduler
scheduler = APScheduler()

def check_stock_and_expiry():
    print("Running daily stock and expiry check...")
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # --- LOW STOCK ITEMS ---
        query_low_stock = """
        SELECT 
            im.ItemID,
            im.itemname AS itemName,
            SUM(CASE WHEN slh.ChangeType = 'IN' THEN slh.QuantityChange ELSE -slh.QuantityChange END) AS CurrentStock,
            im.minQty
        FROM stockledgerhistory slh
        JOIN billitems bi ON slh.BillID = bi.BillID
        JOIN item_master im ON bi.ItemID = im.ItemID
        GROUP BY bi.ItemID, im.itemname, im.minQty
        HAVING CurrentStock < im.minQty;
        """
        cursor.execute(query_low_stock)
        low_stock_items = cursor.fetchall()

        for item in low_stock_items:
            print(f"Low stock alert: {item['itemName']} | Current: {item['CurrentStock']} | Min: {item['minQty']}")

        # --- EXPIRING ITEMS ---
        seven_days_from_now = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d')

        query_expiring = """
        SELECT 
            bi.ItemID,
            im.itemname AS itemName,
            MIN(slh.ItemExpiryDate) AS NearestExpiryDate
        FROM stockledgerhistory slh
        JOIN billitems bi ON slh.BillID = bi.BillID
        JOIN item_master im ON bi.ItemID = im.ItemID
        WHERE slh.ItemExpiryDate IS NOT NULL
          AND slh.ChangeType = 'IN'
          AND slh.ItemExpiryDate <= %s
        GROUP BY bi.ItemID, im.itemname;
        """
        cursor.execute(query_expiring, (seven_days_from_now,))
        expiring_items = cursor.fetchall()

        for item in expiring_items:
            days_left = (item['NearestExpiryDate'] - datetime.now().date()).days
            print(f"Item {item['itemName']} is nearing expiry in {days_left} day(s).")

    finally:
        cursor.close()
        conn.close()


def setup_scheduler(app):
    @scheduler.task('cron', id='daily_check', hour=9)
    def daily_check():
        with app.app_context():
            check_stock_and_expiry()

    scheduler.start()
    setup_scheduler(app)

from datetime import date, timedelta

def check_and_refill_stock():
    print("🔄 Running stock refill check...")
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Query current stock using StockLedgerID directly
        query_low_stock = """
            SELECT 
                slh.StockLedgerID AS ItemID,
                im.itemName,
                SUM(CASE WHEN slh.ChangeType = 'IN' THEN slh.QuantityChange ELSE -slh.QuantityChange END) AS CurrentStock
            FROM stockledgerhistory slh
            JOIN item_master im ON slh.StockLedgerID = im.ItemID
            GROUP BY slh.StockLedgerID, im.itemName
            HAVING CurrentStock <= 10;
        """
        cursor.execute(query_low_stock)
        low_stock_items = cursor.fetchall()

        if not low_stock_items:
            print("No items need refill today.")
            return

        print(f"Found {len(low_stock_items)} items below threshold. Restocking...")

        refill_date = date.today()
        expiry_date = refill_date + timedelta(days=365)  # Default expiry: 1 year from today

        for item in low_stock_items:
            # Skip AC, Mouse, Keyboard
            if item['itemName'] in ['LG 1.5 Ton AC', 'Mouse', 'Keyboard']:
                continue

            # Step 1: Create Purchase Order
            cursor.execute("""
                INSERT INTO purchase_orders (supplier_name, order_date, status)
                VALUES (%s, %s, %s)
            """, ("Auto Supplier", refill_date, "Pending"))
            po_id = cursor.lastrowid

            # Step 2: Add to Purchase Order Details
            cursor.execute("""
                INSERT INTO purchaseorderdetails (purchaseorder_id, item_id, quantity, rate, amount)
                VALUES (%s, %s, %s, %s, %s)
            """, (po_id, item['ItemID'], 100, 5000, 5000 * 100))

            # Step 3: Update Stock Ledger History with new IN entry
            cursor.execute("""
                INSERT INTO stockledgerhistory (StockLedgerID, ChangeType, QuantityChange, BillID, ItemExpiryDate)
                VALUES (%s, 'IN', %s, %s, %s)
            """, (item['ItemID'], 100, po_id, expiry_date))

        conn.commit()
        print("✅ Stock refill completed.")

    except Exception as e:
        print("❌ Error during refill:", str(e))
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

    
    
def setup_scheduler(app):
    @scheduler.task('cron', id='daily_refill_check', hour=9)
    def daily_refill_check():
        with app.app_context():
            check_and_refill_stock()

    scheduler.start()

@app.route('/test-refill')
def test_refill():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Query all items with current stock ≤ 10
        query_low_stock = """
            SELECT 
                bi.ItemID,
                im.itemName,
                SUM(CASE WHEN slh.ChangeType = 'IN' THEN slh.QuantityChange ELSE -slh.QuantityChange END) AS CurrentStock
            FROM stockledgerhistory slh
            JOIN billitems bi ON slh.BillID = bi.BillID
            JOIN item_master im ON bi.ItemID = im.ItemID
            GROUP BY bi.ItemID, im.itemName
            HAVING CurrentStock <= 10
        """
        cursor.execute(query_low_stock)
        low_stock_items = cursor.fetchall()

        if not low_stock_items:
            return "No items need refill."

        # Log found items
        result = []
        refill_date = date.today()
        for item in low_stock_items:
            # Create Purchase Order
            cursor.execute("""
                INSERT INTO purchase_orders (supplier_name, order_date, status)
                VALUES (%s, %s, %s)
            """, ("Auto Supplier", refill_date, "Pending"))
            po_id = cursor.lastrowid

            # Add item to purchaseorderdetails
            cursor.execute("""
                INSERT INTO purchaseorderdetails (purchaseorder_id, item_id, quantity, rate, amount)
                VALUES (%s, %s, %s, %s, %s)
            """, (po_id, item['ItemID'], 100, 5000, 5000 * 100))

            # Add to stockledgerhistory
            cursor.execute("""
                INSERT INTO stockledgerhistory (StockLedgerID, ChangeType, QuantityChange, BillID)
                VALUES (%s, 'IN', %s, %s)
            """, (item['ItemID'], 100, po_id))

            result.append({
                "ItemID": item['ItemID'],
                "itemName": item['itemName'],
                "CurrentStock": item['CurrentStock'],
                "RefillQty": 100,
                "Date": str(refill_date)
            })

        conn.commit()
        print("✅ Auto-refill completed:", result)
        return jsonify({"message": "Refill complete.", "refilled_items": result})

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)})
    finally:
        cursor.close()
        conn.close()


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # CAPTCHA validation
        user_captcha = request.form.get('captcha', '')
        expected_captcha = session.get('captcha', '')

        if user_captcha.strip().upper() != expected_captcha:
            flash('Incorrect CAPTCHA. Please try again.', 'danger')
            return redirect(url_for('login'))

        # Authenticate user
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute('SELECT user_id, username, password FROM user_master WHERE username = %s', (username,))
        result = cursor.fetchone()

        if result and check_password_hash(result['password'], password):
            session['username'] = result['username']

            # Assign role based on username
            if username.lower() == 'admin':
                session['role'] = 'Admin'
            elif username.lower() == 'manager':
                session['role'] = 'Manager'
            else:
                session['role'] = 'User'

            try:
                login_time = datetime.now()

                # Insert login activity
                cursor.execute("""
                    INSERT INTO user_activity (username, login_time)
                    VALUES (%s, %s)
                """, (username, login_time))
                connection.commit()

                # Save activity ID in session to assist during logout (optional)
                session['activity_id'] = cursor.lastrowid

            except Exception as e:
                print("Error inserting login activity:", str(e))
                connection.rollback()

            cursor.close()
            connection.close()

            flash(f"Welcome back, {result['username']}!", "success")
            return redirect(url_for('dashboard'))

        else:
            flash("Invalid username or password", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')



@app.route('/logout')
@login_required
def logout():
    username = session.get('username')
    logout_time = datetime.now()

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Find the most recent login session for this user without a logout time
        cursor.execute("""
            SELECT id, login_time 
            FROM user_activity 
            WHERE username = %s AND logout_time IS NULL
            ORDER BY login_time DESC 
            LIMIT 1
        """, (username,))
        active_session = cursor.fetchone()

        if active_session:
            session_id, login_time = active_session
            total_seconds = int((logout_time - login_time).total_seconds())

            # Update that session with logout time and duration
            cursor.execute("""
                UPDATE user_activity 
                SET logout_time = %s,
                    total_login_seconds = %s
                WHERE id = %s
            """, (logout_time, total_seconds, session_id))
            conn.commit()

    except Exception as e:
        print("Error updating logout time:", str(e))
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

    # Clear session after logging logout
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/user-login-report')
@login_required
def user_login_report():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT 
                ua.username,
                um.first_name,
                um.role,
                ua.login_time,
                ua.logout_time,
                ua.total_login_seconds
            FROM user_activity ua
            JOIN user_master um ON ua.username = um.username
            ORDER BY ua.login_time DESC
            LIMIT 100;
        """)
        data = cursor.fetchall()

        # Format total login seconds into HH:MM:SS
        for row in data:
            total_seconds = row['total_login_seconds']
            if total_seconds is not None:
                row['formatted_login_time'] = str(timedelta(seconds=total_seconds))
            else:
                row['formatted_login_time'] = "Active"  # or "N/A"

        return render_template('user_login_report.html', data=data)
    finally:
        cursor.close()
        conn.close()


if __name__ == '__main__':
    app.run(port=5006, debug=True)
