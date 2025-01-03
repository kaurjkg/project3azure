#Create table in azure sql using query
CREATE TABLE Users (
    Id INT PRIMARY KEY IDENTITY(1,1), -- Auto-incrementing primary key
    Name NVARCHAR(100) NOT NULL, -- Name of the user, up to 100 characters
    DOB DATE, -- Date of birth
    ProfilePictureUrl NVARCHAR(255), -- URL of the profile picture
    IDDocumentPath NVARCHAR(255), -- Path to the ID document
    Username NVARCHAR(50) NOT NULL UNIQUE, -- Username, unique and required
    PasswordHash NVARCHAR(255) NOT NULL -- Hashed password
);

Make sure to allow azure services and resources to access the server in Networking tab of SQL Server

Change the Azure SQL server, database name and admin credentials in app.py

Change name of Storage account, blob container, fileshare and update the connection string
