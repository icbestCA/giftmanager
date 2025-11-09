from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response, get_flashed_messages, request, jsonify, send_from_directory
import requests
from functools import wraps
from mailjet_rest import Client
from datetime import datetime, timedelta
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from authlib.integrations.flask_client import OAuth
import json, secrets
import os
import random
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from dotenv import load_dotenv, set_key, dotenv_values
dotenv_path = os.path.join(os.path.dirname(__file__), '.env') # Load the .env file from the specified path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
load_dotenv(dotenv_path)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Set SameSite attribute to Strict

mailjet_api_key = os.getenv("MAILJET_API_KEY")
mailjet_api_secret = os.getenv("MAILJET_API_SECRET")
mailjet = Client(auth=(mailjet_api_key, mailjet_api_secret), version='v3.1')
ph = PasswordHasher()

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def load_gift_ideas():
    with open('ideas.json', 'r') as file:
        return json.load(file)

def save_gift_ideas(gift_ideas):
    with open('ideas.json', 'w') as file:
        json.dump(gift_ideas, file, indent=4)

def load_users():
    with open('users.json', 'r') as file:
        return json.load(file)

def save_users(users):
    with open('users.json', 'w') as file:
        json.dump(users, file, indent=4)


# Define a decorator for requiring authentication
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Log eerst in.', 'warning')
            return redirect(url_for('login'))
        
        # Check if user is a guest and route doesn't allow guests
        if is_guest_user(session['username']):
            # Check if the route has @guest_allowed decorator
            if not getattr(f, '_guest_allowed', False):
                flash('Deze functie is niet beschikbaar voor gast gebruikers.', 'danger')
                return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if the user is logged in
        if 'username' not in session:
            flash('Log eerst in.', 'warning')
            return redirect(url_for('login'))

        # Load users from the JSON file
        users = load_users()

        # Find the user based on the username stored in the session
        user = next((u for u in users if u['username'] == session['username']), None)

        # Check if the user exists and is an admin
        if not user or not user.get('admin'):
            flash('Beheerder toegang vereist.', 'danger')
            return redirect(url_for('dashboard'))

        # Continue to the original function if the user is an admin
        return f(*args, **kwargs)
    
    return decorated_function

def is_guest_user(username):
    """Check if a user is a guest"""
    users = load_users()
    user = next((u for u in users if u['username'] == username), None)
    return user and user.get('guest', False)

def guest_allowed(f):
    """Decorator to allow guest users access to specific routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Log eerst in.', 'warning')
            return redirect(url_for('login'))
        
        # Check if user is a guest
        if is_guest_user(session['username']):
            return f(*args, **kwargs)
        else:
            # Regular users can always access guest-allowed routes
            return f(*args, **kwargs)
    
    # Mark this function as guest allowed
    decorated_function._guest_allowed = True
    return decorated_function

@app.route('/manifest.json')
def manifest():
    return send_from_directory('static', 'manifest.json')

@app.route('/sw.js')
def service_worker():
    response = make_response(send_from_directory('static', 'sw.js'))
    response.headers['Cache-Control'] = 'no-cache'
    return response

@app.route('/favicon.ico')
def favicon():
    # Redirect to an external URL where your PNG favicon is hosted
    return redirect("https://r2.icbest.ca/favicon-32x32.png")


@app.route('/change_email', methods=['POST'])
@login_required
def change_email():
    # Load users from JSON
    users = load_users()

    # Get the new email from the form
    new_email = request.form['new_email']

    # Update the user's email in the loaded data
    for user in users:
        if user['username'] == session['username']:
            user['email'] = new_email
            break
    else:
        flash('Gebruiker niet gevonden.', 'danger')
        return redirect(url_for('dashboard'))

    # Save the updated data back to the JSON file
    save_users(users)

    flash('E-mail succesvol bijgewerkt.', 'success')
    return redirect(url_for('dashboard'))


def get_currency_symbol():
    return os.getenv('CURRENCY_SYMBOL', '$')

def get_currency_position():
    return os.getenv('CURRENCY_POSITION', 'before')

def format_currency(amount):
    symbol = get_currency_symbol()
    position = get_currency_position()
    
    if position == 'after':
        return f"{amount}{symbol}"
    else:  # before (default)
        return f"{symbol}{amount}"


@app.context_processor
def utility_processor():
    # Use the existing get_full_name function that's already defined
    return dict(
        get_full_name=get_full_name,  # This uses the function you already have
        format_currency=format_currency,
        get_currency_symbol=get_currency_symbol,
        get_currency_position=get_currency_position
    )


#OIDC SUPPORT
oauth = OAuth(app)
oauth.register(
    name="keycloak",
    client_id=os.getenv("OIDC_CLIENT_ID"),
    client_secret=os.getenv("OIDC_CLIENT_SECRET"),
    server_metadata_url=os.getenv("OIDC_SERVER_METADATA_URL"),
    client_kwargs={"scope": "openid profile email phone"},
)

@app.route('/login_oidc')
def login_oidc():
    # Determine the scheme from headers (in case behind reverse proxy)
    forwarded_proto = request.headers.get('X-Forwarded-Proto', request.scheme)
    scheme = forwarded_proto.split(',')[0].strip()  # Handle multi-value headers

    # Generate external HTTPS redirect_uri manually
    redirect_uri = url_for("auth", _external=True, _scheme=scheme)

    # Create nonce and state
    nonce = secrets.token_urlsafe(16)
    state = secrets.token_urlsafe(16)

    # Store in session
    session["nonce"] = nonce
    session["state"] = state

    # Perform OIDC authorization redirect
    return oauth.keycloak.authorize_redirect(redirect_uri, nonce=nonce, state=state)

@app.route("/auth")
def auth():
    """Handle OIDC authentication and user lookup."""
    # Verify state parameter to prevent CSRF
    state = request.args.get("state")
    saved_state = session.pop("state", None)
    if state != saved_state:
        flash("Autorisatie mislukt: ongeldige status.", "danger")
        return redirect(url_for("login"))
    
    try:
        # Retrieve the access token from OIDC provider
        token = oauth.keycloak.authorize_access_token()
    except Exception as e:
        flash("OIDC autorisatie mislukt.", "danger")
        return redirect(url_for("login"))
    
    # Pop nonce from session after use
    nonce = session.pop("nonce", None)
    
    try:
        # Parse ID token and retrieve user info
        user_info = oauth.keycloak.parse_id_token(token, nonce=nonce)
    except Exception as e:
        flash("Fout bij het verwerken van gebruikersinformatie.", "danger")
        return redirect(url_for("login"))
    
    # Retrieve fields dynamically from the environment
    primary_oidc_field = os.getenv("PRIMARY_OIDC_FIELD", "").lower()
    secondary_oidc_field = os.getenv("SECONDARY_OIDC_FIELD", "").lower()
    primary_db_field = os.getenv("PRIMARY_DB_FIELD", "").lower()
    secondary_db_field = os.getenv("SECONDARY_DB_FIELD", "").lower()

    # Get field values from OIDC user info
    primary_oidc_value = user_info.get(primary_oidc_field)
    secondary_oidc_value = user_info.get(secondary_oidc_field)

    # Load users from the JSON file
    users = load_users()

    # Find user in the database based on OIDC fields
    user_in_db = None
    if primary_oidc_value:
        user_in_db = next(
            (user for user in users if user.get(primary_db_field, "").lower() == primary_oidc_value.lower()), 
            None
        )
    if not user_in_db and secondary_oidc_value:
        user_in_db = next(
            (user for user in users if user.get(secondary_db_field, "").lower() == secondary_oidc_value.lower()), 
            None
        )

    if user_in_db:
        # Log in the user by setting the session
        session["username"] = user_in_db["username"]
        flash("Inloggen met OIDC gelukt!", "login_success")
        return redirect(url_for("dashboard"))
    
    # Handle auto-registration if enabled
    if os.getenv("ENABLE_AUTO_REGISTRATION", "false").lower() == "true":
        # Create a new user profile
        new_user = {
            "username": user_info.get("preferred_username"),
            "email": user_info.get("email"),
            "full_name": user_info.get("name"),
            "admin": False,
        }
        users.append(new_user)
        save_users(users)  # Save the updated users list
        session["username"] = new_user["username"]
        
        flash("Nieuw profiel aangemaakt. Vul uw profielinstellingen in.", "info")
        return redirect(url_for("setup_profile"))  # Redirect to profile setup page

    flash("Gebruiker niet gevonden en auto-registratie is uitgeschakeld.", "danger")
    return redirect(url_for("login"))
    

@app.route("/setup_profile", methods=["GET", "POST"])
def setup_profile():
    """Route to handle profile setup after OIDC login."""
    # Load users from JSON
    users = load_users()

    # Retrieve the logged-in username from the session
    username = session.get("username")
    
    # Find the user in `users.json`
    user = next((u for u in users if u["username"] == username), None)
    
    if not user:
        flash("Gebruiker niet gevonden.", "danger")
        return redirect(url_for("login"))

    # Redirect if the avatar URL is already set
    if user.get("avatar"):
        flash("Profiel instellen is niet vereist. Avatar is al ingesteld.", "info")
        return redirect(url_for("dashboard"))
    
    # Check if default login is enabled
    enable_default_login = os.getenv("ENABLE_DEFAULT_LOGIN", "true").lower() == "true"

    if request.method == "POST":
        # Handle form submission to update profile details
        password = request.form.get("password")
        if enable_default_login and password:
            user["password"] = password_hash(password)

        user["birthday"] = request.form["birthday"]
        user["avatar"] = request.form["avatar"]
        
        # Update full name if provided
        user["full_name"] = request.form.get("full_name", user.get("full_name"))
        
        # Save the updated user list to `users.json`
        save_users(users)
        
        flash("Instellen van profiel voltooid!", "success")
        return redirect(url_for("dashboard"))

    # Prefill data for the user (including OIDC data)
    oidc_user_info = {
        "full_name": user.get("full_name", ""),
        "email": user.get("email", "")
    }

    return render_template("setup_profile.html", user=user, oidc_user_info=oidc_user_info, enable_default_login=enable_default_login)

#OIDC END

@app.route('/')
def index():
    # Redirect logged-in users to the dashboard
    if 'username' in session:
        return redirect(url_for('dashboard'))

    try:
        # Load users from the JSON file
        users = load_users()

        # Redirect to setup if there are no users
        if not users:
            return redirect(url_for('setup'))
    except (json.JSONDecodeError, FileNotFoundError) as e:
        # Handle errors and redirect to setup if user file is missing or corrupted
        flash(f"Fout bij het lezen van users.json: {e}", 'danger')
        return redirect(url_for('setup'))

    # Redirect to login if no session exists and setup is complete
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    guests_exist_flag = guests_exist()
    enable_default_login = os.getenv('ENABLE_DEFAULT_LOGIN', 'true').lower() == 'true'
    enable_self_registration = os.getenv('ENABLE_SELF_REGISTRATION', 'false').lower() == 'true'


    # For GET requests, render the login page
    oidc_client_id = os.getenv("OIDC_CLIENT_ID")  # Get OIDC Client ID
    oidc_enabled = bool(oidc_client_id)  # Check if OIDC is enabled
    login_message = read_env_variable("LOGIN_PAGE_MESSAGE") or "No account? Contact a family member to create an account."
    # If default login is disabled, render an OIDC-only login page
    if not enable_default_login:
        return render_template("oidc_only.html", guests_exist=guests_exist_flag)

    if request.method == 'POST':
        input_username = request.form['username'].lower()  # Ensure case-insensitivity
        password = request.form['password']

        try:
            # Load users from the JSON file
            users = load_users()

            # Authenticate user
            for user in users:
                if user['username'].lower() == input_username:
                    # Verify the password hash
                    if verify_password(user['password'], password):
                        session['username'] = user['username']
                        flash('Login succesvol!', 'login_success')
                        return redirect(url_for('dashboard'))
                    else:
                        flash('Onjuist wachtwoord', 'login_error')
                        return render_template('login.html', oidc_enabled=oidc_enabled, login_message=login_message, guests_exist=guests_exist_flag, enable_self_registration=enable_self_registration)

            # No matching username found
            flash('Gebruiker bestaat niet', 'login_error')
        except (json.JSONDecodeError, FileNotFoundError) as e:
            flash(f"Fout bij het lezen van users.json: {e}", 'login_error')
            
    
    return render_template("login.html", oidc_enabled=oidc_enabled, login_message=login_message, guests_exist=guests_exist_flag, enable_self_registration=enable_self_registration)

def guests_exist():
    """Check if any guest users exist in the system"""
    users = load_users()
    return any(user.get('guest') for user in users)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Self-registration page for new users"""
    # Check if self-registration is enabled
    if not os.getenv('ENABLE_SELF_REGISTRATION', 'false').lower() == 'true':
        flash('Zelfregistratie is niet ingeschakeld. Neem contact op met een beheerder.', 'danger')
        return redirect(url_for('login'))
    
    # Get joining code for template
    joining_code = os.getenv('JOINING_CODE', '')
    
    if request.method == 'POST':
        # Get form data
        username = request.form['username'].lower().strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        full_name = request.form['full_name'].strip()
        email = request.form.get('email', '').strip()
        birthday = request.form.get('birthday', '')
        avatar = request.form.get('avatar', 'icons/avatar1.png')
        submitted_joining_code = request.form.get('joining_code', '')
        
        # Validate joining code if one is set in environment
        if joining_code and submitted_joining_code != joining_code:
            flash('Ongeldige code voor inschrijven. Neem contact op met je familie.', 'danger')
            return render_template('register.html', joining_code=joining_code)
        
        # Validate required input
        if not username or not password or not full_name:
            flash('Vul alle verplichte velden in.', 'danger')
            return render_template('register.html', joining_code=joining_code)
        
        if password != confirm_password:
            flash('Wachtwoorden komen niet overeen.', 'danger')
            return render_template('register.html', joining_code=joining_code)
        
        # No password complexity requirements
        
        # Load existing users
        users = load_users()
        
        # Check for duplicate username
        if any(user['username'].lower() == username for user in users):
            flash('Gebruikersnaam bestaat al. Kies alstublieft een andere.', 'danger')
            return render_template('register.html', joining_code=joining_code)
        
        # Check for duplicate email only if email is provided
        if email and any(user.get('email', '').lower() == email.lower() for user in users):
            flash('E-mailadres is al geregistreerd. Gebruik een ander e-mailadres of neem contact op met een beheerder.', 'danger')
            return render_template('register.html', joining_code=joining_code)
        
        # Create new user
        new_user = {
            "username": username,
            "password": password_hash(password),
            "full_name": full_name,
            "email": email,  # Can be empty
            "birthday": birthday,  # Can be empty
            "avatar": avatar,
            "admin": False,
            "guest": False,
            "groups": []  # New users start with no groups by default
        }
        
        # Add user to database
        users.append(new_user)
        save_users(users)
        
        flash('Registratie geslaagd! Je kan nu inloggen.', 'success')
        return redirect(url_for('login'))
    
    # GET request - show registration form
    return render_template('register.html', joining_code=joining_code)


@app.route('/add2/', methods=['GET', 'POST'])
@login_required
def add2():
    # Load data from JSON files
    gift_ideas_data = load_gift_ideas()
    users = load_users()

    # Get the current user's information
    current_user = session['username']
    current_user_data = next((user for user in users if user["username"] == current_user), None)

    if not current_user_data:
        flash("Huidige gebruiker niet gevonden.", "danger")
        return redirect(url_for('dashboard'))

    # Get the current user's groups (default to empty list if not present)
    current_user_groups = current_user_data.get("groups", [])

    # Filter the user list based on groups
    if not current_user_groups:
        # If the current user has no groups, allow them to see all users
        user_list = [
            {"full_name": user["full_name"], "username": user["username"]}
            for user in users
            if not user.get('guest')
        ]
    else:
        # Filter the user list to include only those in the current user's groups
        user_list = [
            {"full_name": user["full_name"], "username": user["username"]}
            for user in users
            if not user.get("groups") or any(group in user.get("groups", []) for group in current_user_groups)
            and not user.get('guest')
        ]

    if request.method == 'POST':
        # Handle the form submission, process the data, and add the idea
        user = request.form['user']
        name = request.form['name']
        description = request.form.get('description', '')
        link = request.form.get('link', '')
        value = request.form.get('value', None)  # Optional field
        image_path = request.form.get('imagePath', '')  # Get the image path from the form

        # Retrieve the logged-in user's username
        added_by = session.get('username')

        # Find the largest gift idea ID
        largest_gift_idea_id = max((idea['gift_idea_id'] for idea in gift_ideas_data), default=0)

        # Create a new idea object
        new_idea = {
            'user_id': user,
            'gift_idea_id': largest_gift_idea_id + 1,
            'gift_name': name,
            'description': description,
            'link': link,
            'value': value,
            'added_by': added_by,  # Track who added the idea
            'bought_by': None,  # Initialize as not bought
            'image_path': image_path  # Store the image URL here
        }

        # Append the new idea to the list
        gift_ideas_data.append(new_idea)

        # Save the updated ideas back to the file
        save_gift_ideas(gift_ideas_data)

        
        # Redirect to the user's gift ideas page
        return redirect(url_for('user_gift_ideas', selected_user_id=user))
    imgenabled = os.getenv('IMGENABLED', 'true').lower() == 'true'
    # Render the "Add Idea" page with the filtered user list
    return render_template('add2.html', user_list=user_list, imgenabled=imgenabled)


@app.route('/add_idea/<selected_user_id>', methods=['GET', 'POST'])
@login_required
def add_idea(selected_user_id):
    # Load data from JSON files
    gift_ideas_data = load_gift_ideas()
    users = load_users()

    # Get the current user's information
    current_user = session['username']
    current_user_data = next((user for user in users if user["username"] == current_user), None)

    if not current_user_data:
        flash("Huidige gebruiker niet gevonden.", "danger")
        return redirect(url_for('dashboard'))

    # Get the current user's groups (default to empty list if not present)
    current_user_groups = current_user_data.get("groups", [])

    # Filter the user list based on groups
    if not current_user_groups:
        # If the current user has no groups, allow them to see all users
        user_list = [
            {"full_name": user["full_name"], "username": user["username"]}
            for user in users
            if not user.get('guest')
        ]
    else:
        # Filter the user list to include only those in the current user's groups
        user_list = [
            {"full_name": user["full_name"], "username": user["username"]}
            for user in users
            if not user.get("groups") or any(group in user.get("groups", []) for group in current_user_groups)
            and not user.get('guest')
        ]

    if request.method == 'POST':
        # Handle the form submission
        user = request.form['user']
        name = request.form['name']
        description = request.form.get('description', '')
        link = request.form.get('link', '')
        value = request.form.get('value', None)  # Optional field
        image_path = request.form.get('imagePath', '')  # Get the image path from the form
        
        # Retrieve the currently logged-in user
        added_by = session.get('username')

        # Find the largest gift idea ID
        largest_gift_idea_id = max((idea['gift_idea_id'] for idea in gift_ideas_data), default=0)

        # Create a new idea object
        new_idea = {
            'user_id': user,
            'gift_idea_id': largest_gift_idea_id + 1,
            'gift_name': name,
            'description': description,
            'link': link,
            'value': value,
            'added_by': added_by,  # Track who added the idea
            'bought_by': None,  # Initialize as not bought
            'image_path': image_path  # Store the image URL here
        }

        # Append the new idea to the list
        gift_ideas_data.append(new_idea)

        # Save the updated gift ideas back to the file
        save_gift_ideas(gift_ideas_data)

        # Flash success message and redirect
        flash(f'Suggestie "{name}" voor gebruiker {user} door {added_by} toegevoegd!', 'success')
        return redirect(url_for('user_gift_ideas', selected_user_id=user))
    imgenabled = os.getenv('IMGENABLED', 'true').lower() == 'true'
    # Render the "Add Idea" page with the user list, gift ideas, and the selected user as default
    return render_template('add_idea.html', user_list=user_list, gift_ideas=gift_ideas_data, default_user=selected_user_id, imgenabled=imgenabled)


@app.route('/delete_idea/<int:idea_id>', methods=['DELETE'])
@login_required
def delete_idea(idea_id):
    # Load gift ideas using helper function
    gift_ideas_data = load_gift_ideas()

    # Find the idea by its ID
    idea = find_idea_by_id(gift_ideas_data, idea_id)

    if idea:
        current_user_username = session['username']  # Use 'username' from the session

        # Check if the idea was added by the current user or if it's in their list
        if idea['added_by'] == current_user_username or idea['user_id'] == current_user_username:
            # Check if the idea is bought
            if idea['bought_by']:
                # Send an email to the buyer using Mailjet
                send_email_to_buyer_via_mailjet(idea['bought_by'], f'{idea["gift_name"]}', 'IDEAS DELETED')

            # Delete the idea
            gift_ideas_data.remove(idea)

            # Save the updated list of gift ideas using the helper function
            save_gift_ideas(gift_ideas_data)

            return '', 204  # Return a response with HTTP status code 204 (no content)
        else:
            flash('Je bent niet bevoegd om deze suggestie te verwijderen.', 'danger')
    else:
        flash('Suggestie niet gevonden', 'danger')

    return '', 403  # Return a response with HTTP status code 403 (forbidden)

def get_user_email_by_username(username):
    # Use the helper function to load users
    users = load_users()

    # Find the user by username
    user = next((u for u in users if u['username'] == username), None)
    return user.get('email') if user else None

def send_email_to_buyer_via_mailjet(buyer_username, idea_name, message_subject):
    # Find the idea bought by the buyer
    gift_ideas_data = load_gift_ideas()
    for idea in gift_ideas_data:
        if idea.get('bought_by') == buyer_username:
            buyer_email = get_user_email_by_username(buyer_username)
            
            if buyer_email:
                text_part = f"This ideas, '{idea_name}',has been deleted but you already BOUGHT IT."

                # Send an email to the buyer using Mailjet
                data = {
                    'Messages': [
                        {
                            'From': {
                                'Email': os.getenv("SYSTEM_EMAIL"),  # Your sender email address
                                'Name': 'GiftManager',
                            },
                            'To': [
                                {
                                    'Email': buyer_email,  # Buyer's email
                                    'Name': 'Buyer Name',
                                },
                            ],
                            'Subject': message_subject,
                            'TextPart': text_part,
                        }
                    ]
                }

                response = mailjet.send.create(data=data)

                if response.status_code == 200:
                    print('Email sent to buyer successfully')
                else:
                    print('Failed to send email to buyer')
            else:
                print(f'Buyer email not found for username: {buyer_username}')
            break

@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    response = make_response(redirect(url_for('login')))
    expires = datetime.utcnow() + timedelta(seconds=5)
    response.set_cookie('session', '', expires=expires)  # Set the session cookie to expire in 5 seconds
    return response


@app.route('/dashboard')
@login_required
@guest_allowed
def dashboard():
    
    # Read user data from the JSON file
    users = load_users()

    # Get the current user's data from the session
    current_user = next((user for user in users if user['username'] == session['username']), None)
    
    if not current_user:
        flash('Gebruikersgegevens niet gevonden', 'danger')
        return redirect(url_for('login'))

    # Check if current user is a guest
    is_guest = current_user.get('guest', False)
    
    # Initialize visible_users
    visible_users = []
    
    if is_guest:
        # Handle guest user access
        access_type = current_user.get('access_type', 'family')
        
        if access_type == 'family':
            # Show users in guest's assigned groups (including guest groups)
            guest_groups = current_user.get('groups', [])
            visible_users = [
                user for user in users
                if user.get('groups') and any(group in guest_groups for group in user['groups'])
                and not user.get('guest')  # Don't show other guests
            ]
        else:  # people access
            # Show specific users assigned to guest
            access_users = current_user.get('access_users', [])
            visible_users = [
                user for user in users
                if user['username'] in access_users and not user.get('guest')
            ]
    else:
        # Regular user logic - SIMPLE VERSION
        current_user_groups = current_user.get('groups', [])
        
        # If current user has no groups, show all non-guest users
        if not current_user_groups:
            visible_users = [user for user in users if not user.get('guest')]
        else:
            # If current user has groups, show users who share groups OR have no groups
            visible_users = [
                user for user in users
                if (not user.get('groups') or any(group in current_user_groups for group in user.get('groups', [])))
                and not user.get('guest')
            ]
        
        # Move current user to top
        if current_user in visible_users:
            visible_users.insert(0, visible_users.pop(visible_users.index(current_user)))

    # Sort the users alphabetically by full name
    sorted_users = sorted(visible_users, key=lambda x: x['full_name'].lower())

    # Prepare the profile information for the current user
    profile_info = {
        'full_name': current_user.get('full_name'),
        'birthday': current_user.get('birthday'),
        'admin': current_user.get('admin'),
        'guest': is_guest
    }

    app_version = "v2.4.5"
    
    # Get assigned users if available in the current user's data
    assigned_users = current_user.get('assigned_users', None)

    # Get flash messages related to passwords
    password_messages = [msg for msg in get_flashed_messages() if 'password' in msg.lower() or 'email' in msg.lower()]

    # Render the dashboard page with the necessary context
    return render_template(
        'dashboard.html',
        profile_info=profile_info,
        users=sorted_users,
        password_messages=password_messages,
        app_version=app_version,
        assigned_users=assigned_users
    )


@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    # Hash the new password before storing it
    newhash = password_hash(new_password)

    # Read the users data from the JSON file
    users = load_users()

    # Find the current user
    current_user = next((user for user in users if user['username'] == session['username']), None)

    if not current_user:
        flash('Gebruiker niet gevonden', 'danger')
        return redirect(url_for('dashboard'))

    # Verify the current password
    if not verify_password(current_user['password'], current_password):
        flash('Huidig wachtwoord is onjuist', 'danger')
        return redirect(url_for('dashboard'))

    # Check if the new password and confirmation match
    if new_password != confirm_password:
        flash('Wachtwoorden komen niet overeen', 'danger')
        return redirect(url_for('dashboard'))

    # Update the password in the user data
    current_user['password'] = newhash

    # Save the updated user data back to the JSON file
    save_users(users)

    flash('Wachtwoord succesvol gewijzigd', 'success')
    return redirect(url_for('dashboard'))

def find_idea_by_id(ideas, idea_id):
    # Iterate through the list of ideas
    for idea in ideas:
        # If the gift_idea_id matches, return the idea
        if idea['gift_idea_id'] == idea_id:
            return idea
    # Return None if no matching idea is found
    return None


@app.route('/mark_as_bought/<int:idea_id>', methods=['POST'])
@login_required
@guest_allowed
def mark_as_bought(idea_id):
    # Load the current gift ideas from the JSON file
    gift_ideas_data = load_gift_ideas()

    # Find the idea by its ID
    idea = find_idea_by_id(gift_ideas_data, idea_id)

    if idea:
        if not idea['bought_by']:
            # Mark the idea as bought by the current user
            idea['bought_by'] = session['username']
            idea['date_bought'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Record the current date and time
            flash(f'"{idea["gift_name"]}" gemarkeerd als gekocht!', 'success')

            # Save the updated gift ideas back to the JSON file
            save_gift_ideas(gift_ideas_data)  # Save the updated list
        else:
            # If already bought, display a warning
            flash(f'"{idea["gift_name"]}" is al gekocht door {idea["gekocht_by"]}.', 'warning')
    else:
        flash('Suggestie niet gevonden', 'danger')

    # Redirect to the user's gift ideas page
    return redirect(url_for('user_gift_ideas', selected_user_id=session['username']))


@app.route('/mark_as_not_bought/<int:idea_id>', methods=['POST'])
@login_required
@guest_allowed
def mark_as_not_bought(idea_id):
    # Load the current gift ideas from the JSON file
    gift_ideas_data = load_gift_ideas()

    # Find the idea by its ID
    idea = find_idea_by_id(gift_ideas_data, idea_id)

    if idea:
        # Check if the idea has already been bought and if the current user is the buyer
        if idea['bought_by'] == session['username']:
            # Mark the idea as not bought by setting 'bought_by' to None (or '' if preferred)
            idea['bought_by'] = None  # Using None is semantically clearer than ''
            idea.pop('date_bought', None)  # Remove the date_bought field if it exists
            flash(f'Merk"{idea["gift_name"]}" gemarkeerd als niet gekocht.', 'success')

            # Save the updated gift ideas back to the JSON file
            save_gift_ideas(gift_ideas_data)  # Save the updated list
        else:
            flash(f'Je hebt niet "{idea["gift_name"]}" gekocht, dus je kunt het niet als niet gekocht markeren.', 'danger')
    else:
        flash('Suggestie niet gevonden', 'danger')

    return '', 204  # Return a response with HTTP status code 204 (no content)


@app.route('/bought_items')
@login_required
@guest_allowed
def bought_items():
    # Load the current gift ideas and users from the JSON files
    gift_ideas_data = load_gift_ideas()
    users = load_users()

    # Filter the gift ideas to include only the ones that are bought by the current user
    bought_items = [idea for idea in gift_ideas_data if idea['bought_by'] == session['username']]

    # Add the full name for each bought item
    for item in bought_items:
        item['recipient_name'] = get_full_name(item['user_id'])

    return render_template('bought_items.html', bought_items=bought_items)


def get_full_name(username):
    users = load_users()  # Load the users from the JSON file
    for user in users:
        if user['username'] == username:
            return user.get('full_name', username)  # Return the full name or fallback to username
    return username  # If no match found, return the username itself


@app.route('/user_gift_ideas/<selected_user_id>')
@login_required
@guest_allowed
def user_gift_ideas(selected_user_id):
    # Check if the selected user is the same as the connected user
    connected_user = session.get('username')
    if selected_user_id == connected_user:
        # Redirect to a different page, e.g., 'my_ideas'
        return redirect(url_for('my_ideas'))

    # Filter the gift ideas for the selected user
    gift_ideas_data = load_gift_ideas()  # Load the gift ideas from the JSON file
    user_gift_ideas = [idea for idea in gift_ideas_data if idea['user_id'] == selected_user_id]

    # Sort the gift ideas by priority, with ideas that have no priority appearing at the bottom
    user_gift_ideas.sort(key=lambda x: (x.get('priority', float('inf')), x['gift_idea_id']))

    # Check if there are no ideas and redirect to the NOIDEA page
    if not user_gift_ideas:
        flash('Geen geschenk suggesties voor deze gebruiker.', 'info')
        return redirect(url_for('noidea'))

    # Call get_full_name function to fetch the user's full name directly in the route
    user_namels = get_full_name(selected_user_id)  # Get the full name based on the selected user ID
    imgenabled = os.getenv('IMGENABLED', 'true').lower() == 'true'
    return render_template('user_gift_ideas.html', user_gift_ideas=user_gift_ideas, user_namels=user_namels, imgenabled=imgenabled)


@app.route('/my_ideas')
@login_required
def my_ideas():
    # Get the connected user
    connected_user = session.get('username')
    
    # Load the gift ideas from the JSON file using load_gift_ideas()
    gift_ideas_data = load_gift_ideas()

    # Filter the gift ideas to include only the ones added by the connected user
    my_gift_ideas = [idea for idea in gift_ideas_data if idea['user_id'] == connected_user and idea.get('added_by') == connected_user]

    # Sort the gift ideas by priority, with ideas that have no priority appearing at the bottom
    my_gift_ideas.sort(key=lambda x: (x.get('priority', float('inf')), x['gift_idea_id']))

    reordering = os.getenv('REORDERING', 'true').lower() == 'true'
    imgenabled = os.getenv('IMGENABLED', 'true').lower() == 'true'
    # Check if there are no ideas and redirect to a different page
    if not my_gift_ideas:
        flash('U heeft geen geschenk suggesties toegevoegd.', 'info')
        return redirect(url_for('noidea'))

    return render_template('my_ideas.html', my_gift_ideas=my_gift_ideas, reordering=reordering, imgenabled=imgenabled)

@app.route('/update_order', methods=['POST'])
@login_required
def update_order():
    # Get the new order data from the request
    data = request.get_json()
    new_order = data.get('order')  # Ensure 'order' includes 'priority'

    # Load the gift ideas from the JSON file using load_gift_ideas()
    gift_ideas_data = load_gift_ideas()

    # Loop to update the priorities of ideas
    for idea in gift_ideas_data:
        for item in new_order:
            if int(idea['gift_idea_id']) == int(item['gift_idea_id']):
                idea['priority'] = item['priority']  # Make sure priority is updated

    # Write the updated data back to the JSON file using save_gift_ideas()
    save_gift_ideas(gift_ideas_data)

    # Option 1: Return a success message as plain text
    return "Order updated successfully!"

@app.route('/noidea')
@login_required
@guest_allowed
def noidea():
    return render_template('noideas.html')

@app.route('/add_user', methods=['GET', 'POST'])
@admin_required
def add_user():
    if request.method == 'POST':
        # Load the latest state from the JSON file to ensure consistency
        users = load_users()  # Using load_users function to read the users

        # Retrieve form data
        username = request.form['username']
        password = request.form['password']
        full_name = request.form['full_name']
        birthday = request.form['birthday']
        email = request.form.get('email')  # Optional field
        avatar = request.form.get('avatar')

        # Hash the password
        hashed = password_hash(password)

        # Check for duplicate usernames
        if any(user['username'] == username for user in users):
            flash('Gebruikersnaam bestaat al!', 'error')
            return redirect(url_for('add_user'))

        # Create a new user object with default groups
        new_user = {
            "username": username,
            "password": hashed,
            "full_name": full_name,
            "birthday": birthday,
            "admin": False,
            "email": email if email else "",
            "avatar": avatar if avatar else "",
            "groups": []  # New user starts with no groups
        }

        # Append the new user to the in-memory list
        users.append(new_user)

        # Save the updated users list back to the JSON file
        save_users(users)  # Using save_users function to write the users to file

        flash('Gebruiker succesvol toegevoegd!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('add_user.html')


@app.route('/edit_idea/<int:idea_id>', methods=['GET', 'POST'])
@login_required
def edit_idea(idea_id):
    # Load the gift ideas from the JSON file
    gift_ideas_data = load_gift_ideas()

    # Find the idea by its ID
    idea = find_idea_by_id(gift_ideas_data, idea_id)

    if idea:
        current_user_username = session['username']  # Use 'username' from the session

        # Check if the idea was added by the current user or if it's in their list
        if idea['added_by'] == current_user_username or idea['user_id'] == current_user_username:
            if request.method == 'POST':
                # Debug: print received form data
                print(f"Received description: {request.form.get('description')}")
                print(f"Received link: {request.form.get('link')}")
                print(f"Received image_path: {request.form.get('image_path')}")  # This is the field for the image path

                # Update idea details with submitted form data
                idea['description'] = request.form.get('description', '')
                idea['link'] = request.form.get('link', '')
                idea['value'] = request.form.get('value', None)
                idea['image_path'] = request.form.get('image_path', '')  # Get the image path from the form

                # Check if the image path is correctly retrieved
                if idea['image_path']:
                    print(f"Image path to save: {idea['image_path']}")
                else:
                    print("No image path provided.")

                # Save the updated gift ideas data back to the JSON file
                save_gift_ideas(gift_ideas_data)

                flash('Suggestie is succesvol bijgewerkt!', 'success')
                return redirect(url_for('user_gift_ideas', selected_user_id=idea['user_id']))
            
            imgenabled = os.getenv('IMGENABLED', 'true').lower() == 'true'
            # Render the edit idea form with pre-filled data
            return render_template('edit_idea.html', idea=idea, imgenabled=imgenabled)
        else:
            flash('Je bent niet bevoegd om deze Suggestie te bewerken.', 'danger')
    else:
        flash('Suggestie niet gevonden', 'danger')

    return redirect(url_for('dashboard'))


# Hash the password using Argon2
def password_hash(password):
    return ph.hash(password)

# Verify the hashed password
def verify_password(hash, password):
    try:
        return ph.verify(hash, password)
    except VerifyMismatchError:
        return False


@app.route('/secret_santa', methods=['GET', 'POST'])
@admin_required
@login_required
def secret_santa():
    # Load users from the JSON file
    users = load_users()

    # Get existing pools
    existing_pools = set()
    for user in users:
        if 'assigned_users' in user:
            existing_pools.update(user['assigned_users'].keys())

    if request.method == 'POST':
        pool_name_to_delete = request.form.get('pool_name_to_delete')

        if pool_name_to_delete:
            # Handle deleting a specific pool
            pool_exists = False
            for user in users:
                if 'assigned_users' in user and pool_name_to_delete in user['assigned_users']:
                    pool_exists = True
                    del user['assigned_users'][pool_name_to_delete]

            if not pool_exists:
                flash(f'Pool "{pool_name_to_delete}" bestaat niet.', 'error')
            else:
                # Remove the corresponding instructions file if it exists
                try:
                    os.remove(f'santa_inst_{pool_name_to_delete}.txt')
                except FileNotFoundError:
                    pass  # Ignore if the file does not exist

                # Save the updated users list
                save_users(users)
                flash(f'Pool "{pool_name_to_delete}" is verwijderd!', 'success')

            return redirect(url_for('dashboard'))  # Redirect to dashboard after deletion

        else:
            # Handle creating Secret Santa assignments
            selected_participants = request.form.getlist('participants')
            secret_santa_instructions = request.form.get('instructions', '')  # Default to an empty string if not provided
            pool_name = request.form.get('pool_name')

            if not pool_name:
                flash('Pool naam is verplicht!', 'error')
                return redirect(url_for('secret_santa'))

            if len(selected_participants) < 2:
                flash('Je heeft minstens 2 deelnemers nodig voor Secret Santa!', 'error')
                return redirect(url_for('secret_santa'))

            # Shuffle and assign participants
            shuffled_participants = selected_participants[:]
            random.shuffle(shuffled_participants)

            assignments = {}
            for i, participant in enumerate(shuffled_participants):
                # Assign each participant the next one in the shuffled list, looping around
                assignments[participant] = shuffled_participants[(i + 1) % len(shuffled_participants)]

            # Save the assignments to the users JSON
            for user in users:
                if user['username'] in assignments:
                    if 'assigned_users' not in user:
                        user['assigned_users'] = {}
                    user['assigned_users'][pool_name] = assignments[user['username']]

            # Save the updated users data
            save_users(users)

            # Save the instructions to a text file specific to the pool
            with open(f'santa_inst_{pool_name}.txt', 'w') as file:
                file.write(secret_santa_instructions or '')  # Ensure it writes a string, even if empty

            flash('Secret Santa opdrachten zijn gemaakt!', 'success')
            return redirect(url_for('secret_santa_assignments'))

    return render_template('secret_santa.html', users=users, existing_pools=sorted(existing_pools))


@app.route('/secret_santa_assignments', methods=['GET'])
@login_required
@guest_allowed
def secret_santa_assignments():
    current_user = session['username']

    # Use the pre-defined load_users function to read users data
    users = load_users()

    assigned_users = {}
    for user in users:
        if user['username'] == current_user and 'assigned_users' in user:
            assigned_users = user['assigned_users']  # Dictionary of pool names and assigned users

    if not assigned_users:
        flash("Je hebt nog geen Secret Santa opdrachten.", "error")
        return redirect(url_for('secret_santa'))

    # Load instructions for each pool
    pool_instructions = {}
    for pool_name in assigned_users.keys():
        try:
            with open(f'santa_inst_{pool_name}.txt', 'r') as file:
                pool_instructions[pool_name] = file.read()
        except FileNotFoundError:
            pool_instructions[pool_name] = "No specific instructions provided."

    # Pass the 'assigned_users' and 'pool_instructions' to the template
    return render_template('secret_santa_assignment.html', assigned_users=assigned_users, pool_instructions=pool_instructions)


@app.route('/admin')
@admin_required
def admin_dashboard():
    containerid = os.getenv("CONTAINER_ID")
    container_restart = bool(containerid)
    return render_template('admin_dashboard.html', container_restart=container_restart)

@app.route('/users', methods=['GET', 'POST'])
@admin_required
def manage_users():

    # Load users and filter out guests immediately
    users = [user for user in load_users() if not user.get('guest', False)]


    if request.method == 'POST':
        username = request.form.get('username')

        # Handle delete
        if 'delete_user' in request.form:
            users = [user for user in users if user['username'] != username]
            flash('Gebruiker succesvol verwijderd!', 'success')

        # Handle toggle admin
        elif 'toggle_admin' in request.form:
            for user in users:
                if user['username'] == username:
                    user['admin'] = bool(int(request.form['toggle_admin']))
                    flash('Beheerder status bijgewerkt!', 'success')
                    break

        # Handle user details update
        else:
            updated_name = request.form.get('name')
            updated_email = request.form.get('email')
            updated_password = request.form.get('password')
            updated_avatar = request.form.get('avatar')

            for user in users:
                if user['username'] == username:
                    user['full_name'] = updated_name
                    user['email'] = updated_email if updated_email else user.get('email', 'N/A')
                    user['avatar'] = updated_avatar if updated_avatar else user.get('avatar', 'avatar1.png')  # Default avatar if missing
                    if updated_password:
                        user['password'] = ph.hash(updated_password)  # Hash the new password
                    flash('Gebruiker is succesvol bijgewerkt!', 'success')
                    break

        # Save updated users to the JSON file using the pre-defined function
        save_users(users)

    # Transform users into tuples for the template
    users_data = [
        (
            user['username'], 
            user['full_name'], 
            user.get('email', 'N/A'),  # Default to 'N/A' if email is missing
            user.get('avatar', 'avatar1.png'),  # Default to placeholder if avatar is missing
            user.get('admin', 'N/A')  # Default to 'N/A' if admin is missing
        )
        for user in users
    ]

    return render_template('manage_users.html', users=users_data)

@app.route('/edit_email_settings', methods=['GET', 'POST'])
@admin_required
def edit_email_settings():
    if request.method == 'POST':
        # Retrieve form values
        mailjet_api_key = request.form.get('MAILJET_API_KEY', None)
        mailjet_api_secret = request.form.get('MAILJET_API_SECRET', None)
        system_email = request.form.get('SYSTEM_EMAIL', None)

        try:
            # Read current .env content
            with open(dotenv_path, 'r') as file:
                env_content = file.readlines()

            # Update the variables in the .env file
            new_env_content = []
            for line in env_content:
                key, _, value = line.partition('=')
                key = key.strip()
                if key == 'MAILJET_API_KEY' and mailjet_api_key:
                    new_env_content.append(f"MAILJET_API_KEY='{mailjet_api_key}'\n")
                elif key == 'MAILJET_API_SECRET' and mailjet_api_secret:
                    new_env_content.append(f"MAILJET_API_SECRET='{mailjet_api_secret}'\n")
                elif key == 'SYSTEM_EMAIL' and system_email:
                    new_env_content.append(f"SYSTEM_EMAIL='{system_email}'\n")
                else:
                    new_env_content.append(line)

            # Write updated content back to .env
            with open(dotenv_path, 'w') as file:
                file.writelines(new_env_content)

            # Reload the .env file to reflect changes
            load_dotenv(dotenv_path, override=True)

            flash("E-mail instellingen succesvol bijgewerkt!", "success")
        except Exception as e:
            flash(f"Er is een fout opgetreden: {e}", "danger")
        return redirect(url_for('edit_email_settings'))

    # Reload the .env file before fetching current settings
    load_dotenv(dotenv_path, override=True)  # Ensure we override old values
    current_settings = {
        'MAILJET_API_KEY': '******',  # Mask sensitive values
        'MAILJET_API_SECRET': '******',  # Mask sensitive values
        'SYSTEM_EMAIL': os.getenv('SYSTEM_EMAIL', ''),
    }
    return render_template('edit_email_settings.html', settings=current_settings)

def read_env_variable(key, dotenv_path=dotenv_path):
    try:
        with open(dotenv_path, 'r') as file:
            for line in file:
                if line.strip().startswith(f"{key}="):
                    return line.strip().split('=', 1)[1].strip("'").strip('"')
    except FileNotFoundError:
        return None
    return None

@app.route('/edit_login_message', methods=['GET', 'POST'])
@admin_required  # Assumes an @admin_required decorator exists for access control
def edit_login_message():
    if request.method == 'POST':
        new_message = request.form.get('login_message', '').strip()
        if new_message:
            try:
                # Update the .env file
                with open(dotenv_path, 'r') as file:
                    lines = file.readlines()

                with open(dotenv_path, 'w') as file:
                    for line in lines:
                        if line.strip().startswith("LOGIN_PAGE_MESSAGE="):
                            file.write(f"LOGIN_PAGE_MESSAGE='{new_message}'\n")
                        else:
                            file.write(line)

                flash("Login bericht succesvol bijgewerkt!", "success")
            except Exception as e:
                flash(f"Fout bij bijwerken login bericht: {e}", "danger")
        else:
            flash("Bericht mag niet leeg zijn.", "danger")

        return redirect(url_for('edit_login_message'))

    # Fetch the current login message directly from .env
    current_message = read_env_variable("LOGIN_PAGE_MESSAGE") or "Geen account? Neem contact op met een familielid om een account aan te maken."
    return render_template('edit_login_message.html', current_message=current_message)

def delete_old_gift_ideas():

    # Read the number of days from the environment variable
    threshold_days = int(read_env_variable("DELETE_DAYS", dotenv_path) or 30)

    # Calculate the threshold time
    threshold_time = datetime.now() - timedelta(days=threshold_days)

    try:
        # Load gift ideas using the helper function
        gift_ideas_data = load_gift_ideas()

        # Prepare a list to hold the updated gift ideas
        updated_gift_ideas = []
        removed_count = 0

        # Loop through each gift idea and check if it should be removed
        for idea in gift_ideas_data:
            if 'date_bought' in idea:
                date_bought = datetime.strptime(idea['date_bought'], '%Y-%m-%d %H:%M:%S')

                # If the gift idea's date_bought is older than the threshold, remove it
                if date_bought < threshold_time:
                    removed_count += 1
                    continue  # Skip this gift idea

            # Otherwise, keep this gift idea
            updated_gift_ideas.append(idea)

        # Save the updated list of gift ideas using the helper function
        save_gift_ideas(updated_gift_ideas)

        # Record the last execution time
        last_execution_time = datetime.now().isoformat()
        with open('last_execution_time.txt', 'w') as time_file:
            time_file.write(last_execution_time)

        # Return the number of removed ideas
        return removed_count

    except Exception as e:
        print(f"Error: {e}")
        return 0  # Return 0 if an error occurs

@app.route('/delete_old_gift_ideas', methods=['GET', 'POST'])
@admin_required
def delete_old_gift_ideas_page():
    current_days = read_env_variable("DELETE_DAYS", dotenv_path) or 30
    if request.method == 'POST':
        try:
            # Delete old gift ideas and get the count of deleted rows
            deleted_count = delete_old_gift_ideas()

            # Flash success message with the number of deleted rows
            flash(f"{deleted_count} cadeau suggesties ouder dan de drempelwaarde zijn succesvol verwijderd.", "success")

            # Render the result to the template
            return render_template('delete_old_gift_ideas.html', deleted_count=deleted_count)

        except Exception as e:
            flash(f"Fout bij verwijderen oude cadeau suggesties: {e}", "danger")
            return render_template('delete_old_gift_ideas.html', deleted_count=0, error_message=str(e))

    # GET request: Just display the page
    return render_template('delete_old_gift_ideas.html', deleted_count=0, current_days=current_days)


@app.route('/change_delete_days', methods=['GET', 'POST'])
@admin_required
def change_delete_days():
    if request.method == 'POST':
        # Get the new days value from the form
        new_days = request.form.get('days')

        if new_days:
            try:
                new_days = int(new_days)

                # Update the .env file with the new value
                set_key(".env", "DELETE_DAYS", str(new_days))  # Update the DELETE_DAYS value

                flash(f"Het aantal dagen om oude cadeau suggesties te verwijderen is bijgewerkt naar {new_days}.", "success")
                return redirect(url_for('change_delete_days'))

            except ValueError:
                flash("Ongeldig aantal dagen ingevoerd. Voer een geldig nummer in.", "danger")
        else:
            flash("Geef een waarde op voor het aantal dagen.", "danger")

    # Get the current value of the DELETE_OLD_GIFTS_DAYS from the .env file
    current_days = read_env_variable("DELETE_DAYS", dotenv_path) or 30
    return render_template('delete_old_gift_ideas.html', current_days=current_days)

@app.route('/setupadmin', methods=['GET', 'POST'])
def setup():
    """Handles the creation of an admin user when no users exist in the system."""

    # Check if users.json already exists and contains users
    users_data = load_users()
    if users_data:  # If there are any users in the file
        flash('Gebruikers zijn al geconfigureerd. Setup pagina is niet beschikbaar.', 'info')
        return redirect(url_for('login'))  # Redirect to the login page or another appropriate route

    if request.method == 'POST':
        # Gather form data
        admin_username = request.form.get('admin_username')
        admin_password = request.form.get('admin_password')
        admin_email = request.form.get('admin_email')
        full_name = request.form.get('full_name')
        birthday = request.form.get('birthday')
        avatar_url = request.form.get('avatar')  # Selected avatar from the dropdown

        # Hash the admin password
        admin_password_hash = ph.hash(admin_password)

        # Create the admin user dictionary
        admin_user = {
            "username": admin_username,
            "password": admin_password_hash,
            "email": admin_email,
            "full_name": full_name,
            "birthday": birthday,
            "avatar": avatar_url,
            "admin": True
        }

        # Append the admin user to the existing list of users
        users_data.append(admin_user)

        # Save the updated users list
        save_users(users_data)

        flash('Beheerdersaccount succesvol aangemaakt. Configureer de omgevingsvariabelen a.u.b.', 'success')
        return redirect(url_for('setupenv'))  # Redirect to the setupenv route

    return render_template('setupadmin.html')


@app.route('/setupenv', methods=['GET', 'POST'])
def setupenv():
    referer = request.headers.get('Referer')
    if not referer or '/setupadmin' not in referer:
        flash('U moet toegang krijgen tot deze pagina vanuit de setupadmin route.', 'error')
        return redirect(url_for('login'))  # Redirect to login if not accessed correctly

    if request.method == 'POST':
        # Collect form data
        delete_days = request.form.get('DELETE_DAYS', '30')  # Default to 30 days
        env_variables = {
            "MAILJET_API_KEY": request.form.get('MAILJET_API_KEY', ''),
            "MAILJET_API_SECRET": request.form.get('MAILJET_API_SECRET', ''),
            "SYSTEM_EMAIL": request.form.get('SYSTEM_EMAIL', ''),
            "DELETE_DAYS": delete_days,
            "OIDC_CLIENT_ID": request.form.get('OIDC_CLIENT_ID', ''),
            "OIDC_CLIENT_SECRET": request.form.get('OIDC_CLIENT_SECRET', ''),
            "OIDC_SERVER_METADATA_URL": request.form.get('OIDC_SERVER_METADATA_URL', ''),
            "OIDC_LOGOUT_URL": request.form.get('OIDC_LOGOUT_URL', ''),
            "PRIMARY_OIDC_FIELD": request.form.get('PRIMARY_OIDC_FIELD', 'email'),
            "SECONDARY_OIDC_FIELD": request.form.get('SECONDARY_OIDC_FIELD', 'preferred_username'),
            "PRIMARY_DB_FIELD": request.form.get('PRIMARY_DB_FIELD', 'email'),
            "SECONDARY_DB_FIELD": request.form.get('SECONDARY_DB_FIELD', 'username'),
            "ENABLE_AUTO_REGISTRATION": request.form.get('ENABLE_AUTO_REGISTRATION', 'false'),
        }

        # Save each variable to .env file
        for key, value in env_variables.items():
            set_key(".env", key, value)

        flash('Omgevingsvariabelen succesvol opgeslagen!', 'success')
        return redirect(url_for('index'))

    # Render the setup environment page
    return render_template('setupenv.html', current_env=os.environ)

@app.route('/setup_oidc', methods=['GET', 'POST'])
@admin_required
def setup_oidc():
    if request.method == 'POST':
        # Collect form data and validate required fields
        oidc_env_variables = {
            "OIDC_CLIENT_ID": request.form.get("OIDC_CLIENT_ID", '').strip(),
            "OIDC_CLIENT_SECRET": request.form.get("OIDC_CLIENT_SECRET", '').strip(),
            "OIDC_SERVER_METADATA_URL": request.form.get("OIDC_SERVER_METADATA_URL", '').strip(),
            "OIDC_LOGOUT_URL": request.form.get("OIDC_LOGOUT_URL", '').strip(),
            "PRIMARY_OIDC_FIELD": request.form.get("PRIMARY_OIDC_FIELD", 'email').strip(),
            "SECONDARY_OIDC_FIELD": request.form.get("SECONDARY_OIDC_FIELD", 'preferred_username').strip(),
            "PRIMARY_DB_FIELD": request.form.get("PRIMARY_DB_FIELD", 'email').strip(),
            "SECONDARY_DB_FIELD": request.form.get("SECONDARY_DB_FIELD", 'username').strip(),
            "ENABLE_AUTO_REGISTRATION": request.form.get("ENABLE_AUTO_REGISTRATION", 'false').strip(),
            "ENABLE_DEFAULT_LOGIN": request.form.get("ENABLE_DEFAULT_LOGIN", 'true').strip(),
        }

        # Check for missing fields
        missing_fields = [key for key, value in oidc_env_variables.items() if not value]
        if missing_fields:
            flash(f"Verplichte velden ontbreken: {', '.join(missing_fields)}", 'danger')
            return render_template('setup_oidc.html', current_values=oidc_env_variables)

        try:
            # Save each variable to the .env file
            for key, value in oidc_env_variables.items():
                set_key(dotenv_path, key, value)

            flash('OIDC instellingen succesvol opgeslagen!', 'success')
            return redirect(url_for('setup_oidc'))  # Redirect to home page after saving
        except Exception as e:
            flash(f"Fout bij opslaan van OIDC instellingen: {e}", "danger")
            return render_template('setup_oidc.html', current_values=oidc_env_variables)

    # For GET requests, load the current values of OIDC-related environment variables
    try:
        # Load the .env file directly using the path
        load_dotenv(dotenv_path, override=True)
    except FileNotFoundError:
        flash("Omgeving bestand niet gevonden. Maak een nieuw aan.", "warning")
    
    current_values = {
        "OIDC_CLIENT_ID": os.getenv("OIDC_CLIENT_ID", ''),
        "OIDC_CLIENT_SECRET": os.getenv("OIDC_CLIENT_SECRET", ''),
        "OIDC_SERVER_METADATA_URL": os.getenv("OIDC_SERVER_METADATA_URL", ''),
        "OIDC_LOGOUT_URL": os.getenv("OIDC_LOGOUT_URL", ''),
        "PRIMARY_OIDC_FIELD": os.getenv("PRIMARY_OIDC_FIELD", 'email'),
        "SECONDARY_OIDC_FIELD": os.getenv("SECONDARY_OIDC_FIELD", 'preferred_username'),
        "PRIMARY_DB_FIELD": os.getenv("PRIMARY_DB_FIELD", 'email'),
        "SECONDARY_DB_FIELD": os.getenv("SECONDARY_DB_FIELD", 'username'),
        "ENABLE_AUTO_REGISTRATION": os.getenv("ENABLE_AUTO_REGISTRATION", 'false'),
        "ENABLE_DEFAULT_LOGIN": os.getenv("ENABLE_DEFAULT_LOGIN", 'true'),
    }

    return render_template('setup_oidc.html', current_values=current_values)

# Families 
# Start
@app.route('/families', methods=['GET', 'POST'])
@admin_required
def manage_groups():
    # Load user data using the helper function
    users = load_users()

    # Extract existing groups from the users
    groups = get_visible_groups(users)

    if request.method == 'POST':
        # Handle adding a new group
        new_group_name = request.form.get('new_group_name')
        assigned_users = request.form.getlist('assigned_users')

        if new_group_name:
            for user in users:
                # Add the new group to selected users
                if user['username'] in assigned_users:
                    if 'groups' not in user:
                        user['groups'] = []
                    if new_group_name not in user['groups']:
                        user['groups'].append(new_group_name)

            # Save updated user data after adding the group using the helper function
            save_users(users)

            flash('Nieuwe groep succesvol toegevoegd!', 'success')
            return redirect(url_for('manage_groups'))

    return render_template('manage_groups.html', users=users, groups=groups)


@app.route('/update_group_assignments', methods=['POST'])
@admin_required
def update_group_assignments():
    # Load user data using the helper function
    users = load_users()

    # Extract existing groups from the users
    groups = sorted(set(group for user in users for group in user.get('groups', [])))

    # Handle group assignments (checkboxes)
    for user in users:
        user_groups = []
        for group in groups:
            checkbox_name = f"{user['username']}[{group}]"
            if request.form.get(checkbox_name):
                user_groups.append(group)
        user['groups'] = user_groups

    # Save updated user data after assignments using the helper function
    save_users(users)

    flash('Groep opdrachten succesvol bijgewerkt!', 'success')
    return redirect(url_for('manage_groups'))

# Families 
# End
@app.route('/setup_advanced', methods=['GET'])
@admin_required
def setup_advanced():
    current_ID = read_env_variable("CONTAINER_ID")
    current_reorder = read_env_variable("REORDERING")
    images = read_env_variable("IMGENABLED")
    current_currency_symbol = get_currency_symbol()
    current_currency_position = get_currency_position()
    enable_self_registration = os.getenv('ENABLE_SELF_REGISTRATION', 'false').lower() == 'true'
    joining_code = os.getenv('JOINING_CODE', '')
    return render_template('advanced.html', current_ID=current_ID, current_reorder=current_reorder, images=images, current_currency_symbol=current_currency_symbol,
                         current_currency_position=current_currency_position, enable_self_registration=enable_self_registration,
                         joining_code=joining_code)

# Route to update CONTAINER_ID (POST request)
@app.route('/update_containerid', methods=['POST'])
@admin_required
def update_containerid():
    containerid = request.form.get('containerid', '').strip()
    if containerid:
        set_key(".env", "CONTAINER_ID", containerid)
    return redirect(url_for('setup_advanced'))

# Route to update REORDERING (POST request)
@app.route('/update_reordering', methods=['POST'])
@admin_required
def update_reordering():
    reordering = request.form.get('reordering', 'true').strip()
    set_key(".env", "REORDERING", reordering)
    return redirect(url_for('setup_advanced'))

# Route to update IMGENABLED (POST request)
@app.route('/update_images', methods=['POST'])
@admin_required
def update_images():
    images = request.form.get('images', 'true').strip()
    set_key(".env", "IMGENABLED", images)
    return redirect(url_for('setup_advanced'))

@app.route('/rundl')
def run_script():
    try:
        # Call the function and get the number of removed gift ideas
        removed_count = delete_old_gift_ideas()

        # Prepare the output message
        script_output = f"Successfully removed {removed_count} gift ideas."

        # Return the output to the user
        return render_template('script_output.html', script_output=script_output)

    except Exception as e:
        error_message = f"Error occurred while running delete_old_gift_ideas: {e}\n\n"
        return render_template('script_output.html', script_output=error_message)
    


def fetch_og_image(url):
    try:
        response = requests.get(url, verify=False)
        response.raise_for_status()  # Raise an error for bad status codes
        soup = BeautifulSoup(response.text, 'html.parser')

        # Try to get the og:image tag
        og_image = soup.find('meta', property='og:image')
        if og_image:
            image_url = og_image.get('content')
            # Convert relative URL to absolute URL if necessary
            if not image_url.startswith('http'):
                image_url = urljoin(url, image_url)
            return image_url

        # Fallback to twitter:image if og:image is not found
        twitter_image = soup.find('meta', attrs={'name': 'twitter:image'})
        if twitter_image:
            image_url = twitter_image.get('content')
            if not image_url.startswith('http'):
                image_url = urljoin(url, image_url)
            return image_url

        # Fallback to image_src if og:image and twitter:image are not found
        image_src = soup.find('link', rel='image_src')
        if image_src:
            image_url = image_src.get('href')
            if not image_url.startswith('http'):
                image_url = urljoin(url, image_url)
            return image_url

        return None  # No image found
    except Exception as e:
        print(f"Error fetching OG image: {e}")
        return None

@app.route('/fetch_og_image', methods=['GET'])
def get_og_image():
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "URL parameter is required"}), 400

    og_image_url = fetch_og_image(url)
    if og_image_url:
        return jsonify({"og_image_url": og_image_url})
    else:
        return jsonify({"error": "No OG image found"}), 404    

@app.route('/manage_guest_users', methods=['GET', 'POST'])
@admin_required
def manage_guest_users():
    users = load_users()
    
    if request.method == 'POST':
        display_name = request.form.get('display_name')
        password = request.form.get('password')
        access_type = request.form.get('access_type', 'family')
        
        # Generate guest username
        base_username = "guest_" + display_name.lower().replace(' ', '_').replace("'", "")
        username = base_username
        counter = 1
        
        # Ensure unique username
        while any(user['username'] == username for user in users):
            username = f"{base_username}_{counter}"
            counter += 1
        
        # Create guest user
        new_guest = {
            "username": username,
            "password": password_hash(password),
            "full_name": display_name,
            "admin": False,
            "guest": True,
            "access_type": access_type,
            "groups": [],
            "access_users": []
        }
        
        # Set access based on type
        if access_type == 'family':
            new_guest['groups'] = request.form.getlist('access_groups')
        else:  # people access
            new_guest['access_users'] = request.form.getlist('access_users')
            
            # Create private family groups for each selected person
            private_groups = []
            for selected_username in new_guest['access_users']:
                # Create a unique private family name
                private_family_name = f"guest_{username}_{selected_username}"
                private_groups.append(private_family_name)
                
                # Add this private family to the guest user
                if private_family_name not in new_guest['groups']:
                    new_guest['groups'].append(private_family_name)
                
                # Add the private family to the selected user WITHOUT removing them from global access
                for user in users:
                    if user['username'] == selected_username:
                        if 'groups' not in user:
                            user['groups'] = []
                        if private_family_name not in user['groups']:
                            user['groups'].append(private_family_name)
                        # User keeps their existing groups and remains in global access
        
        users.append(new_guest)
        save_users(users)
        flash('Gast gebruiker succesvol aangemaakt!', 'success')
        return redirect(url_for('manage_guest_users'))
    
    # Get all available groups and users for the form
    all_groups = sorted(set(
        group for user in users 
        for group in user.get('groups', [])
    ))
    
    # Get non-guest users for people access
    all_users = [user for user in users if not user.get('guest')]
    
    # Get existing guest users
    guest_users = [user for user in users if user.get('guest')]
    
    return render_template('manage_guest_users.html', 
                         guest_users=guest_users,
                         all_groups=all_groups,
                         all_users=all_users)


@app.route('/delete_guest_user/<username>', methods=['POST'])
@admin_required
def delete_guest_user(username):
    users = load_users()
    gift_ideas_data = load_gift_ideas()
    
    # Find the guest user before deleting to get their details
    guest_user = next((user for user in users if user['username'] == username), None)
    
    if guest_user:
        # 1. Remove ALL guest's private family groups from all users
        for user in users:
            if 'groups' in user:
                # Remove any group that starts with "guest_{username}_"
                user['groups'] = [group for group in user['groups'] 
                                if not group.startswith(f"guest_{username}_")]
                # Also remove the main guest family group if it exists
                user['groups'] = [group for group in user['groups'] 
                                if group != f"guest_{username}"]
        
        # 2. Delete entirely the gift ideas that were bought by this guest
        updated_gift_ideas = []
        deleted_count = 0
        
        for idea in gift_ideas_data:
            if idea.get('bought_by') == username:
                # Skip adding this idea to the updated list (effectively deleting it)
                deleted_count += 1
                continue
            updated_gift_ideas.append(idea)
        
        # 3. Remove the guest user
        users = [user for user in users if user['username'] != username]
        
        # Save both updated datasets
        save_users(users)
        save_gift_ideas(updated_gift_ideas)
        
        flash(f'Gast gebruiker {username} is succesvol verwijderd! Alle privé groepen verwijderd en {deleted_count} gekochte geschenk suggesties verwijderd.', 'success')
    else:
        flash('Gast gebruiker niet gevonden.', 'danger')
    
    return redirect(url_for('manage_guest_users'))


@app.route('/guest_login', methods=['POST'])
def guest_login():
    password = request.form['password']
    
    users = load_users()
    
    # Look for a guest user with matching password
    for user in users:
        if user.get('guest') and verify_password(user['password'], password):
            session['username'] = user['username']
            flash('Gast login succesvol!', 'login_success')
            return redirect(url_for('dashboard'))
    
    flash('Ongeldig gast wachtwoord', 'login_error')
    return redirect(url_for('login'))

def get_visible_groups(users):
    """Get all groups except guest private families"""
    all_groups = set()
    for user in users:
        for group in user.get('groups', []):
            # Exclude guest private families (they start with 'guest_')
            if not group.startswith('guest_'):
                all_groups.add(group)
    return sorted(all_groups)

@app.route('/update_currency_settings', methods=['POST'])
@admin_required
def update_currency_settings():
    symbol = request.form.get('currency_symbol', '$')
    position = request.form.get('currency_position', 'before')
    
    set_key(".env", "CURRENCY_SYMBOL", symbol)
    set_key(".env", "CURRENCY_POSITION", position)
    
    flash('Valuta instellingen bijgewerkt! Start opnieuw op om wijzigingen te zien', 'success')
    return redirect(url_for('setup_advanced'))

@app.route('/update_self_registration_settings', methods=['POST'])
@admin_required
def update_self_registration_settings():
    """Update self-registration settings"""
    enable_self_registration = request.form.get('enable_self_registration', 'false')
    joining_code = request.form.get('joining_code', '')
    
    set_key(".env", "ENABLE_SELF_REGISTRATION", enable_self_registration)
    set_key(".env", "JOINING_CODE", joining_code)
    
    flash('Zelfregistratie instellingen succesvol bijgewerkt!', 'success')
    return redirect(url_for('setup_advanced'))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)