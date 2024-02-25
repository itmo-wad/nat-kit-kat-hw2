Overview

This web application focuses on implementing a secure authentication system with user data stored in MongoDB. It includes both basic and advanced features to ensure a robust user authentication experience.

Basic Features
1. Authentication Feature
1.1 Listen on localhost:5000
The application is set up to run locally on http://localhost:5000.

1.2 Render Authentication Form
A clean and user-friendly authentication form is provided at the landing page http://localhost:5000/, allowing users to input their credentials.

1.3 Redirect to Profile Page on Successful Authentication
Upon successful authentication, users are seamlessly redirected to their personalized profile page.

1.4 Profile Page for Authenticated Users Only
Accessing http://localhost:5000/profile displays the user's profile. Unauthorized access leads users back to the authentication form.

1.5 User Credentials Stored in MongoDB
Usernames and hashed passwords are securely stored in a MongoDB database.

Advanced Features
2. Additional Features
2.1 Create New Account and Display Profile
Users can create new accounts, and each user's profile is dynamically displayed with data specific to their account.

2.2 Password Hashing, Logout, and Password Change
Enhanced security measures include password hashing, logout functionality, and the ability for users to change their passwords.

2.3 Update Profile Picture
Users, including new ones, can upload and update their profile pictures. New users are assigned a default profile picture.

2.4 Update Profile Information
A user-friendly interface allows users to update their profile information, ensuring that changes persist in the database.