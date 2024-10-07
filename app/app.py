from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, abort, make_response, get_flashed_messages
from functools import wraps
from mailjet_rest import Client
from datetime import datetime, timedelta
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import json, subprocess, hashlib
import os
import random
from dotenv import load_dotenv, set_key, dotenv_values
load_dotenv()


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # Set SameSite attribute to Strict
app.config['UPLOAD_FOLDER'] = './'  # Directory where files are stored
app.config['ALLOWED_EXTENSIONS'] = {'json'}

TRUSTED_PROXY = os.getenv("TRUSTED_PROXY")
USERNAME_HEADER = OS.getenv("USERNAME_HEADER")

mailjet_api_key = os.getenv("MAILJET_API_KEY")
mailjet_api_secret = os.getenv("MAILJET_API_SECRET")
mailjet = Client(auth=(mailjet_api_key, mailjet_api_secret), version='v3.1')
ph = PasswordHasher()


def update_gift_ideas_json(data):
    with open('ideas.json', 'w') as file:
        json.dump(data, file, indent=4)

# Load user data from the JSON file
with open('users.json', 'r') as file:
    users = json.load(file)

# Load gift ideas data from the JSON file
with open('ideas.json', 'r') as file:
    gift_ideas_data = json.load(file)
    
def check_username_header(request):
    username = ""
    if request.remote_addr == TRUSTED_PROXY or request.remote_addr == "127.0.0.1":
        user = request.headers.get(USERNAME_HEADER)
        if user:
            username = user
    return username

# Define a decorator for requiring authentication
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/change_email', methods=['POST'])
@login_required
def change_email():
    newemail = request.form['new_email']

    # Update the user's password in the JSON data (you may need to modify this)
    for user in users:
        if user['username'] == session['username']:
            user['email'] = newemail
            break

    # Save the updated JSON data back to the file (you may need to modify this)
    with open('users.json', 'w') as file:
        json.dump(users, file, indent=4)

    flash('success')
    return redirect(url_for('dashboard'))


@app.context_processor
def utility_processor():
    def get_full_name(username):
        with open('users.json', 'r') as file:
            users = json.load(file)
            for user in users:
                if user['username'] == username:
                    return user['full_name']
        return username  # Return the username if the full name is not found

    return dict(get_full_name=get_full_name)



@app.route('/')
def index():
    if 'username' in session or check_username_header(request):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/rundl')
def run_script():
    script_name = 'delete.py'
    try:
        result = subprocess.run(['python', script_name], capture_output=True, text=True, check=True)
        script_output = result.stdout
        return render_template('script_output.html', script_output=script_output)
    except subprocess.CalledProcessError as e:
        error_message = f"Error occurred while running {script_name}: {e}\n\n"
        error_message += e.stderr  # Append the error details from stderr
        return render_template('script_output.html', script_output=error_message)
    
@app.route('/runemail')
def run_email():
    script_name = 'mailjet.py'
    try:
        result = subprocess.run(['python', script_name], capture_output=True, text=True, check=True)
        script_output = result.stdout
        return render_template('script_output.html', script_output=script_output)
    except subprocess.CalledProcessError as e:
        error_message = f"Error occurred while running {script_name}: {e}\n\n"
        error_message += e.stderr  # Append the error details from stderr
        return render_template('script_output.html', script_output=error_message)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        input_username = request.form['username'].lower()  # Convert to lowercase
        password = request.form['password']

        # Check if the username exists
        for user in users:
            if user['username'].lower() == input_username:
                try:
                    # Verify the password against the stored hash using Argon2
                    if ph.verify(user['password'], password):
                        session['username'] = user['username']
                        flash('Login successful!', 'success')
                        return redirect(url_for('dashboard'))
                except VerifyMismatchError:
                    flash('Invalid login credentials. Please try again.', 'danger')
                    return render_template('login.html')

        flash('Invalid login credentials. Please try again.', 'danger')
    elif request.method == "GET":
        user = check_username_header(request)
        messages = get_flashed_messages(with_categories=True)
        if ('danger','User data not found') in messages:
            return render_template('login.html', messages=messages)
        elif user:
            session['username'] = user
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))

    return render_template('login.html')
@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        user_email = request.form['email']
        user_name = request.form['name']
        user_feedback = request.form['feedback']

        # Send feedback via Mailjet
        data = {
            'Messages': [
                {
                    'From': {
                        'Email': os.getenv("SYSTEM_EMAIL"),
                        'Name': 'GiftManager Feedback',
                    },
                    'To': [
                        {
                            'Email': os.getenv("FEED_SEND"),  # Your email as the recipient
                            'Name': 'Admin',
                        },
                    ],
                    'Subject': 'Feedback',
                    'TextPart': f'Name: {user_name}\nEmail: {user_email}\nFeedback: {user_feedback}',
                }
            ]
        }

        response = mailjet.send.create(data=data)

        if response.status_code == 200:
            flash('Feedback sent successfully', 'success')
        else:
            flash('Failed to send feedback', 'danger')

        return redirect(url_for('feedback'))

    return render_template('feedback.html')



@app.route('/add2/', methods=['GET', 'POST'])
@login_required
def add2():

    if request.method == 'POST':
        # Handle the form submission, process the data, and add the idea
        user = request.form['user']
        name = request.form['name']
        description = request.form.get('description', '')
        link = request.form.get('link', '')
        value = request.form.get('value', None)  # Optional field

        # You can customize how you retrieve the currently logged-in user here
        # For example, if you're storing the username in the session:
        added_by = session.get('username')
        
        # Find the largest gift idea ID
        largest_gift_idea_id = max(idea['gift_idea_id'] for idea in gift_ideas_data)


        # Create a new idea object
        new_idea = {
            'user_id': user,
            'gift_idea_id': largest_gift_idea_id + 1,
            'gift_name': name,
            'description': description,
            'link': link,
            'value': value,
            'added_by': added_by,  # Track who added the idea
            'bought_by': None  # Initialize as not bought
        }

        # Append the new idea to the list
        gift_ideas_data.append(new_idea)

        # Update JSON file with the new data
        update_gift_ideas_json(gift_ideas_data)

        flash(f'Idea "{name}" added for user {user} by {added_by}!', 'success')

        return redirect(url_for('user_gift_ideas', selected_user_id=user))

    # Read user data from the JSON file
    with open('users.json', 'r') as file:
        users = json.load(file)

    # Extract the user list from the JSON data
    user_list = [{"full_name": user["full_name"], "username": user["username"]} for user in users]

    # Render the "Add Idea" page with the user list and the selected user as default
    return render_template('add2.html', user_list=user_list)




# Route for the "Add Idea" page with a default user based on the selected userhash
@app.route('/add_idea/<selected_user_id>', methods=['GET', 'POST'])
@login_required
def add_idea(selected_user_id):

    if request.method == 'POST':
        # Handle the form submission, process the data, and add the idea
        user = request.form['user']
        name = request.form['name']
        description = request.form.get('description', '')
        link = request.form.get('link', '')
        value = request.form.get('value', None)  # Optional field
        
        # You can customize how you retrieve the currently logged-in user here
        # For example, if you're storing the username in the session:
        added_by = session.get('username')

        # Find the largest gift idea ID
        largest_gift_idea_id = max(idea['gift_idea_id'] for idea in gift_ideas_data)

        # Create a new idea object
        new_idea = {
            'user_id': user,
            'gift_idea_id': largest_gift_idea_id + 1,
            'gift_name': name,
            'description': description,
            'link': link,
            'value': value,
            'added_by': added_by,  # Track who added the idea
            'bought_by': None  # Initialize as not bought
        }

        # Append the new idea to the list
        gift_ideas_data.append(new_idea)

        # Update JSON file with the new data
        update_gift_ideas_json(gift_ideas_data)

        flash(f'Idea "{name}" added for user {user} by {added_by}!', 'success')

        return redirect(url_for('user_gift_ideas', selected_user_id=user))

    # Extract the user list for the dropdown from the users data
    user_list = [{"full_name": user["full_name"], "username": user["username"]} for user in users]

    # Render the "Add Idea" page with the user list, gift ideas, and the selected user as default
    return render_template('add_idea.html', user_list=user_list, gift_ideas=gift_ideas_data, default_user=selected_user_id)



@app.route('/delete_idea/<int:idea_id>', methods=['DELETE'])
@login_required
def delete_idea(idea_id):
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
            update_gift_ideas_json(gift_ideas_data)  # Update JSON file
            return '', 204  # Return a response with HTTP status code 204 (no content)
        else:
            flash('You are not authorized to delete this idea.', 'danger')
    else:
        flash('Idea not found', 'danger')

    return '', 403  # Return a response with HTTP status code 403 (forbidden)

def send_email_to_buyer_via_mailjet(buyer_username, idea_name, message_subject):
    # Find the idea bought by the buyer
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

def get_user_email_by_username(username):
    # Assuming you have a list of user data in JSON
    for user in users:
        if user.get('username') == username:
            return user.get('email')
    return None  # Return None if user email not found


@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    response = make_response(redirect(url_for('login')))
    expires = datetime.utcnow() + timedelta(seconds=5)
    response.set_cookie('session', '', expires=expires)  # Set the session cookie to expire in 5 seconds
    return response


@app.route('/dashboard')
@login_required
def dashboard():
    # Read user data from the JSON file
    with open('users.json', 'r') as file:
        users = json.load(file)

    # Sort the user list alphabetically by full_name
    sorted_users = sorted(users, key=lambda x: x['full_name'].lower())

    current_user = next((user for user in sorted_users if user['username'] == session['username']), None)

        # Move the current user to the top of the list
    if current_user:
        sorted_users.remove(current_user)
        sorted_users.insert(0, current_user)

    # Find the user's data by matching the username in the session
    user_data = next((user for user in users if user['username'] == session['username']), None)

    messages = get_flashed_messages()
    password_messages = [msg for msg in messages if 'password' in msg.lower()]

    assigned_users = None
    if current_user and 'assigned_users' in current_user:
        assigned_users = current_user['assigned_users']

    if user_data:
        # Display user information on the dashboard
        profile_info = {
            'full_name': user_data['full_name'],
            'birthday': user_data['birthday']
        }
    else:
        # Handle the case when user data is not found
        flash('User data not found', 'danger')
        return redirect(url_for('login'))

    return render_template('dashboard.html', profile_info=profile_info, users=sorted_users, password_messages=password_messages, assigned_users=assigned_users)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    newhash = password_hash(new_password)

    # Retrieve the user's current password from the JSON data (you may need to modify this)
    for user in users:
        if user['username'] == session['username']:
            user_password = user['password']
            break
    else:
        flash('User not found', 'danger')
        return redirect(url_for('dashboard'))

    # Check if the current password matches the stored password
    if not verify_password_hash(user_password, current_password):

        flash('Actual password incorrect', 'danger')
        return redirect(url_for('dashboard'))

    # Check if the new password and confirmation match
    if new_password != confirm_password:
        flash('New password and confirmation do not match', 'danger')
        return redirect(url_for('dashboard'))

    # Update the user's password in the JSON data (you may need to modify this)
    for user in users:
        if user['username'] == session['username']:
            user['password'] = newhash
            break

    # Save the updated JSON data back to the file (you may need to modify this)
    with open('users.json', 'w') as file:
        json.dump(users, file, indent=4)

    flash('Password successfully modified', 'success')
    return redirect(url_for('dashboard'))

def find_idea_by_id(ideas, idea_id):
    for idea in ideas:
        if idea['gift_idea_id'] == idea_id:
            return idea
    return None

@app.route('/mark_as_bought/<int:idea_id>', methods=['POST'])
@login_required
def mark_as_bought(idea_id):
    idea = find_idea_by_id(gift_ideas_data, idea_id)

    if idea:
        if not idea['bought_by']:
            idea['bought_by'] = session['username']
            idea['date_bought'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Record the date and time
            flash(f'Marked "{idea["gift_name"]}" as bought!', 'success')
            update_gift_ideas_json(gift_ideas_data)  # Update JSON file
        else:
            flash(f'"{idea["gift_name"]}" has already been bought by {idea["bought_by"]}.', 'warning')
    else:
        flash('Idea not found', 'danger')

    return redirect(url_for('user_gift_ideas', selected_user_id=session['username']))

@app.route('/mark_as_not_bought/<int:idea_id>', methods=['POST'])
@login_required
def mark_as_not_bought(idea_id):
    # Find the idea by its ID
    idea = find_idea_by_id(gift_ideas_data, idea_id)

    if idea:
        # Check if the idea has already been bought and if the current user is the buyer
        if idea['bought_by'] == session['username']:
            # Mark the idea as not bought by setting 'bought_by' to an empty string or None
            idea['bought_by'] = ''
            idea.pop('date_bought', None)  # Remove the date
            flash(f'Marked "{idea["gift_name"]}" as not bought.', 'success')
            update_gift_ideas_json(gift_ideas_data)  # Update JSON file
        else:
            flash(f'You did not buy "{idea["gift_name"]}", so you cannot mark it as not bought.', 'danger')
    else:
        flash('Idea not found', 'danger')

    return '', 204  # Return a response with HTTP status code 204 (no content)

@app.route('/bought_items')
@login_required
def bought_items():
    # Filter the gift ideas to include only the ones that are bought by the current user
    bought_items = [idea for idea in gift_ideas_data if idea['bought_by'] == session['username']]

    # Add the full name for each bought item
    for item in bought_items:
        item['recipient_name'] = get_full_name(item['user_id'])

    return render_template('bought_items.html', bought_items=bought_items)


def get_full_name(user_id):
    # Assuming you have a list of user data in JSON
    for user in users:
        if user.get('username') == user_id:
            return user.get('full_name')
    return None 




def get_user_full_name(selected_user_id):
    # Assuming you have a list of user data in JSON
    for user in users:
        if user.get('username') == selected_user_id:
            return user.get('full_name')
    return None 


@app.route('/user_gift_ideas/<selected_user_id>')
@login_required
def user_gift_ideas(selected_user_id):
    # Check if the selected user is the same as the connected user
    connected_user = session.get('username')
    if selected_user_id == connected_user:
        # Redirect to a different page, e.g., 'my_ideas'
        return redirect(url_for('my_ideas'))

    # Filter the gift ideas for the selected user
    gift_ideas_data = read_gift_ideas()
    user_gift_ideas = [idea for idea in gift_ideas_data if idea['user_id'] == selected_user_id]

    # Sort the gift ideas by priority, with ideas that have no priority appearing at the bottom
    user_gift_ideas.sort(key=lambda x: (x.get('priority', float('inf')), x['gift_idea_id']))

    # Check if there are no ideas and redirect to the dashboard
    if not user_gift_ideas:
        flash('No gift ideas for this user.', 'info')
        return redirect(url_for('noidea'))

    user_namels = get_user_full_name(selected_user_id)

    return render_template('user_gift_ideas.html', user_gift_ideas=user_gift_ideas, user_namels=user_namels)

def read_gift_ideas():
    with open('ideas.json', 'r') as file:
        return json.load(file)

@app.route('/my_ideas')
@login_required
def my_ideas():
    # Get the connected user
    connected_user = session.get('username')
    # Read the gift ideas from the JSON file
    gift_ideas_data = read_gift_ideas()
    # Filter the gift ideas to include only the ones added by the connected user
    my_gift_ideas = [idea for idea in gift_ideas_data if idea['user_id'] == connected_user and idea.get('added_by') == connected_user]

    # Sort the gift ideas by priority, with ideas that have no priority appearing at the bottom
    my_gift_ideas.sort(key=lambda x: (x.get('priority', float('inf')), x['gift_idea_id']))

    # Check if there are no ideas and redirect to a different page
    if not my_gift_ideas:
        flash('You haven\'t added any gift ideas.', 'info')
        return redirect(url_for('noidea'))

    return render_template('my_ideas.html', my_gift_ideas=my_gift_ideas)

@app.route('/update_order', methods=['POST'])
@login_required
def update_order():
    # Get the new order data from the request
    data = request.get_json()
    new_order = data.get('order')  # Ensure 'order' includes 'priority'

    # Loop to update the priorities of ideas
    for idea in gift_ideas_data:
        for item in new_order:
            if int(idea['gift_idea_id']) == int(item['gift_idea_id']):
                idea['priority'] = item['priority']  # Make sure priority is updated

    # Write the updated data back to the JSON file
    update_gift_ideas_json(gift_ideas_data)

    # Option 1: Return a success message as plain text
    return "Order updated successfully!"


@app.route('/noidea')
@login_required
def noidea():
    return render_template('noideas.html')

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        full_name = request.form['full_name']
        birthday = request.form['birthday']
        email = request.form.get('email')  # Use request.form.get to handle optional fields
        avatar = request.form.get('avatar')

        hashed = password_hash(password)
        # Validate the form data, e.g., check for duplicate usernames, password requirements, etc.

        # Create a new user object with the provided data
        new_user = {
            "username": username,
            "password": hashed,
            "full_name": full_name,
            "birthday": birthday,
            "email": email if email else "",  # Add email if provided, else empty string
            "avatar": avatar if avatar else "",  # Add avatar if provided, else empty string
        }

        # Add the new user to your user database (users list)
        users.append(new_user)

        # Update the JSON file with the new user data
        with open('users.json', 'w') as file:
            json.dump(users, file, indent=4)

        # Redirect to the dashboard or another appropriate page
        flash(f'User "{username}" added successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_user.html')

@app.route('/edit_idea/<int:idea_id>', methods=['GET', 'POST'])
@login_required
def edit_idea(idea_id):
    # Find the idea by its ID
    idea = find_idea_by_id(gift_ideas_data, idea_id)

    if idea:
        current_user_username = session['username']  # Use 'username' from the session

        # Check if the idea was added by the current user or if it's in their list
        if idea['added_by'] == current_user_username or idea['user_id'] == current_user_username:
            if request.method == 'POST':
                # Update idea details with submitted form data
                idea['description'] = request.form.get('description', '')
                idea['link'] = request.form.get('link', '')
                idea['value'] = request.form.get('value', None)

                # Update the JSON file with the modified data
                update_gift_ideas_json(gift_ideas_data)

                flash('Idea updated successfully!', 'success')
                return redirect(url_for('user_gift_ideas', selected_user_id=idea['user_id']))
            
            # Render the edit idea form with pre-filled data
            return render_template('edit_idea.html', idea=idea)
        else:
            flash('You are not authorized to edit this idea.', 'danger')
    else:
        flash('Idea not found', 'danger')

    return redirect(url_for('dashboard'))


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        user = next((u for u in users if u['username'] == session['username']), None)
        if not user or not user.get('admin'):
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function



@app.route('/delete_default_profiles', methods=['GET', 'POST'])
@login_required
def delete_default_profiles():
    flag_file = 'default_profiles_deleted.flag'
    
    # Check if the flag file exists
    if os.path.exists(flag_file):
        flash('Default profiles have already been deleted.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Load user data from the JSON file
    with open('users.json', 'r') as file:
        users = json.load(file)
    
    if request.method == 'POST':
        password = request.form['password']
        current_user = session['username']

        # Ensure the current user is not one of the default profiles
        if current_user in ['user2', 'demo']:
            flash('You cannot delete default profiles while logged in as a default profile.', 'danger')
            return redirect(url_for('dashboard'))

        # Check if there are more than two profiles
        if len(users) <= 2:
            flash('Cannot delete default profiles. Less than or equal to two profiles exist.', 'danger')
            return redirect(url_for('dashboard'))

        # Verify the password
        if not check_password(current_user, password):
            flash('Incorrect password. Please try again.', 'danger')
            return redirect(url_for('delete_default_profiles'))

        # Delete the default profiles
        users = [user for user in users if user['username'] not in ['user2', 'demo']]

        # Grant admin status to the current user
        for user in users:
            if user['username'] == current_user:
                user['admin'] = True
                break

        # Update the JSON file
        with open('users.json', 'w') as file:
            json.dump(users, file, indent=4)

        # Create the flag file to indicate that the default profiles have been deleted
        with open(flag_file, 'w') as file:
            file.write('default profiles deleted')

        flash('Default profiles deleted successfully. You have been granted admin status.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('delete_default_profiles.html')

def check_password(username, password):
    with open('users.json', 'r') as file:
        users = json.load(file)
        for user in users:
            if user['username'] == username:
                return verify_password_hash(user['password'], password)
    return False

# Hash the password using Argon2
def password_hash(password):
    return ph.hash(password)

# Verify the hashed password
def verify_password_hash(hash, password):
    try:
        return ph.verify(hash, password)
    except VerifyMismatchError:
        return False


field_explanations = {
    "FEED_SEND": "adress email you wish to receve the feedback from the form  ",
    "MAILJET_API_KEY": "Mailjet API key",
    "MAILJET_API_SECRET": "Mailjet API secret key",
    "SECRET_KEY": "Flask secret key for browser data",
    "SYSTEM_EMAIL": "System email that will send the mesaage related to the app, must be allowed in mailjet",
    "DELETE_DAYS":"days delete"
}
# Function to get current .env values
def get_env_values():
    return dotenv_values()

@app.route('/setup', methods=['GET'])
@login_required
@admin_required
def setup():
    env_values = get_env_values()
    return render_template('setup.html', env_values=env_values, explanations=field_explanations)


@app.route('/update', methods=['POST'])
@login_required
@admin_required
def update_env():
    for key in field_explanations.keys():
        if key in request.form:
            new_value = request.form[key]
            set_key('.env', key, new_value)
    return redirect(url_for('setup'))

@app.route('/upload_files', methods=['POST'])
@login_required
@admin_required
def upload_files():
    ideas_file = request.files.get('ideas_file')
    users_file = request.files.get('users_file')

    if ideas_file and allowed_file(ideas_file.filename):
        ideas_file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'ideas.json'))

    if users_file and allowed_file(users_file.filename):
        users_file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'users.json'))

    return redirect(url_for('setup'))


@app.route('/download_files', methods=['GET'])
@login_required
@admin_required
def download_files():
    # Handle file downloads
    file = request.args.get('file')
    if file not in ['ideas.json', 'users.json']:
        abort(404)
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file)
    
    if not os.path.exists(file_path):
        abort(404)
    
    return send_file(file_path, as_attachment=True)


def allowed_file(filename):
    """
    Check if the file has a valid extension.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']



@app.route('/secret_santa', methods=['GET', 'POST'])
@admin_required
@login_required
def secret_santa():
    if request.method == 'POST':
        pool_name_to_delete = request.form.get('pool_name_to_delete')

        if pool_name_to_delete:
            # Handle deleting a specific pool
            with open('users.json', 'r+') as file:
                users = json.load(file)
                pool_exists = False
                for user in users:
                    if 'assigned_users' in user and pool_name_to_delete in user['assigned_users']:
                        pool_exists = True
                        del user['assigned_users'][pool_name_to_delete]

                if not pool_exists:
                    flash(f'Pool "{pool_name_to_delete}" does not exist.', 'error')
                else:
                    # Remove the corresponding instructions file
                    try:
                        os.remove(f'santa_inst_{pool_name_to_delete}.txt')
                    except FileNotFoundError:
                        pass

                    # Save the updated data back to the file
                    file.seek(0)
                    json.dump(users, file, indent=4)
                    file.truncate()

                    flash(f'Pool "{pool_name_to_delete}" has been deleted!', 'success')
            return redirect(url_for('dashboard'))  # Redirect to dashboard after deletion

        else:
            # Handle creating Secret Santa assignments
            selected_participants = request.form.getlist('participants')
            secret_santa_instructions = request.form.get('instructions', '')  # Default to an empty string if not provided
            pool_name = request.form.get('pool_name')

            if not pool_name:
                flash('Pool name is required!', 'error')
                return redirect(url_for('secret_santa'))

            if len(selected_participants) < 2:
                flash('You need at least 2 participants for Secret Santa!', 'error')
                return redirect(url_for('secret_santa'))

            # Shuffle and assign
            shuffled_participants = selected_participants[:]
            random.shuffle(shuffled_participants)

            assignments = {}
            for i, participant in enumerate(shuffled_participants):
                # Assign each participant the next one in the shuffled list, looping around
                assignments[participant] = shuffled_participants[(i + 1) % len(shuffled_participants)]

            # Save the assignments to the users JSON
            with open('users.json', 'r+') as file:
                users = json.load(file)
                for user in users:
                    if user['username'] in assignments:
                        if 'assigned_users' not in user:
                            user['assigned_users'] = {}
                        user['assigned_users'][pool_name] = assignments[user['username']]

                # Save the updated assignments back to the file
                file.seek(0)
                json.dump(users, file, indent=4)
                file.truncate()

            # Save the instructions to a text file specific to the pool
            with open(f'santa_inst_{pool_name}.txt', 'w') as file:
                file.write(secret_santa_instructions or '')  # Ensure it writes a string, even if empty

            flash('Secret Santa assignments have been made!', 'success')
            return redirect(url_for('secret_santa_assignments'))

    # Load users from the JSON
    with open('users.json', 'r') as file:
        users = json.load(file)

    return render_template('secret_santa.html', users=users)


@app.route('/secret_santa_assignments', methods=['GET'])
@login_required
def secret_santa_assignments():
    current_user = session['username']

    with open('users.json', 'r') as file:
        users = json.load(file)

    assigned_users = {}
    for user in users:
        if user['username'] == current_user and 'assigned_users' in user:
            assigned_users = user['assigned_users']  # Dictionary of pool names and assigned users

    if not assigned_users:
        flash("You don't have any Secret Santa assignments yet.", "error")
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


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
