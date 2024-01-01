# Gift Ideas Web Application

The Gift Ideas Web Application is a simple web application built using Flask, allowing users to manage and share gift ideas.

## Features

- **User Authentication:** Users can create accounts, log in, and log out. All the passwords are stored encrypted with SHA-1, within a JSON, separated from the ideas.
- **User Profiles:** Users can view and update their password and email.
- **Add Gift Ideas:** Users can add new gift ideas, providing details such as the gift name, description and link.
- **Ideas Editing** Users that added an ideas can modify it but only the link and description to prevent someone modifying the compelete sense of it.
- **Mark as Bought:** Users can mark gift ideas as bought or not bought to avoid the others user buying the same gift twice.
- **View Gift Ideas:** Users can view their own gift ideas and those of other users, but can't see the ideas added to his list by other user and the user can't see if his own idea was bought. To keep the surprise.
- **Delete Gift Ideas:** Users can delete gift ideas they added to someone else or those in their list, because everyone can chnage mind. If the gift ideas is already buyed it will send an email to the buyer to notify him that the idea he bought was deleted.
- **Bought Items:** Users can see what items they bought by clicking the small cart on the dashboard.
- **Adding profiles:** Every authenticated users can add a new profile to the site.
- **Email Notifications:** Buyers receive email notifications when a gift marked as bought is deleted, there's also a feedback page the website owner will receive the feedback by email.

## Installation

- For testing use ``` flask run ``` You will need to signup and install the Mailjet module ``` pip install mailjet-rest ``` 

  **Lines to edit in app.py**
- API keys mailjet ``` Lines 11 and 12 ``` 
- Add your email for the service or your personnal one ``` Lines 119, 124, 288 ```
- Add the name of the service ``` Line 289 ```


## To Do

- **Add tutorials and FAQ** Add tutorials to the feedback page
- **Add email password reset** User could reset their password on their own without asking the admin

