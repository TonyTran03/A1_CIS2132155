CREATE TABLE Roles (
    id SERIAL PRIMARY KEY,
    role_name VARCHAR(50) UNIQUE NOT NULL
);

CREATE TABLE Department (
    dnumber SERIAL PRIMARY KEY,
    dname VARCHAR(50) UNIQUE NOT NULL
);


CREATE TABLE Users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role_id INT REFERENCES Roles(id) ON DELETE SET NULL,
    department_id INT REFERENCES Department(dnumber) ON DELETE SET NULL 
);
ALTER TABLE users ALTER COLUMN department_id DROP NOT NULL;

CREATE TABLE Employee (
    id SERIAL PRIMARY KEY,              
    name VARCHAR(50) NOT NULL,                                   
    salary DECIMAL(10, 2),                  
    dno INT REFERENCES Department(dnumber) ON DELETE SET NULL, 
    user_id INT REFERENCES Users(id) ON DELETE SET NULL   
);

CREATE TABLE projects (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    department_id INT NOT NULL REFERENCES department(dnumber)
);


INSERT INTO Roles (id, role_name)
VALUES
(1, 'Super Admin'),
(2,'Department Admin'),
(3, 'Normal User');

CREATE VIEW DepartmentProjects AS
SELECT p.*, d.dname
FROM Projects p
JOIN Department d ON p.department_id = d.dnumber    