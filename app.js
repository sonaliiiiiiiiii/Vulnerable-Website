const express = require('express');
const mysql = require('mysql');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const moment = require('moment');
const app = express();
const port = 4500;

// Middleware to serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Session middleware
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 3600000 } // 1 hour
}));

// MySQL connection setup
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '', // Replace with your MySQL password
  database: 'ADBMS_proj',
  multipleStatements: true
});

connection.connect((err) => {
  if (err) {
    console.error('Error connecting to the database: ', err);
    return;
  }
  console.log('Connected to the database!');
});

// Middleware for parsing JSON and URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Set views directory and view engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Authentication middleware
const authenticateUser = (req, res, next) => {
  if (req.session.userID) {
    next();
  } else {
    res.redirect('/login');
  }
};

// Admin middleware
const requireAdmin = (req, res, next) => {
  if (req.session.userRole === 'admin') {
    next();
  } else {
    res.status(403).send('Access denied');
  }
};

// Audit logging function
const auditLog = (action, tableName, recordID, details, req) => {
  const userID = req.session.userID;
  const query = 'INSERT INTO AuditLog (UserID, Action, TableName, RecordID, Details) VALUES (?, ?, ?, ?, ?)';
  connection.query(query, [userID, action, tableName, recordID, details], (err) => {
    if (err) console.error('Error logging audit:', err);
  });
};

// Auth Routes
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.get('/signup', (req, res) => {
  res.render('signup', { error: null });
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.log('Error destroying session:', err);
      return res.status(500).send('Could not log out.');
    }
    res.redirect('/login'); // Redirect to login page after logout
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Intentionally vulnerable SQL query
  const query = `SELECT * FROM User WHERE Username = '${username}' AND Password = '${password}'`;

  console.log(`Executing SQL Query: ${query}`); // Debugging output

  connection.query(query, (err, results) => {
    if (err) {
      console.error('SQL Error:', err);
      return res.send(`
        <h3>Error executing query:</h3>
        <p>${err.sqlMessage}</p>
        <h4>Executed Query:</h4>
        <code>${query}</code>
      `);
    }

    // Show results if any
    if (results.length > 0) {
      let tableRows = results.map(row => `
        <tr>
          <td>${row.UserID || 'NULL'}</td>
          <td>${row.Username || 'NULL'}</td>
          <td>${row.Password || 'NULL'}</td>
          <td>${row.Role || 'NULL'}</td>
        </tr>
      `).join('');

      return res.send(`
        <h3>Login Successful!</h3>
        <h4>Executed Query:</h4>
        <code>${query}</code>

        <h3>SQL Injection Output:</h3>
        <table border="1">
          <tr>
            <th>UserID</th>
            <th>Username</th>
            <th>Password</th>
            <th>Role</th>
          </tr>
          ${tableRows}
        </table>
      `);
    } else {
      return res.send(`
        <h3>Invalid Credentials</h3>
        <h4>Executed Query:</h4>
        <code>${query}</code>
      `);
    }
  });
});


app.post('/signup', async (req, res) => {
  const { username, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    connection.query(
      'INSERT INTO User (Username, Password, Role) VALUES (?, ?, ?)',
      [username, hashedPassword, role || 'staff'],
      (err, result) => {
        if (err) {
          if (err.code === 'ER_DUP_ENTRY') {
            return res.render('signup', { error: 'Username already exists' });
          }
          throw err;
        }
        res.redirect('/login');
      }
    );
  } catch (err) {
    res.render('signup', { error: 'Error creating account' });
  }
});

app.get('/logout', (req, res) => {
  auditLog('Logout', 'User', req.session.userID, 'User logged out', req);
  req.session.destroy();
  res.redirect('/login');
});

app.get('/audit', authenticateUser, requireAdmin, (req, res) => {
  connection.query('SELECT * FROM AuditLog ORDER BY Timestamp DESC', (err, results) => {
    if (err) throw err;
    res.render('audit', { auditLogs: results });
  });
});



// Main Route
app.get('/', authenticateUser, (req, res) => {
  res.render('index', { 
    userRole: req.session.userRole,
    username: req.session.username 
  });
});

// Menu Routes
app.get('/menu1', authenticateUser, (req, res) => {
  connection.query('SELECT * FROM Patient', (err, results) => {
    if (err) throw err;
    res.render('menu1', { 
      patients: results,
      userRole: req.session.userRole 
    });
  });
});

app.get('/menu2', authenticateUser, (req, res) => {
  connection.query('SELECT * FROM Doctor', (err, results) => {
    if (err) throw err;
    res.render('menu2', { 
      doctors: results,
      userRole: req.session.userRole 
    });
  });
});

app.get('/menu3', authenticateUser, (req, res) => {
  const query = `
    SELECT 
      a.*, 
      d.Name as DoctorName, 
      p.Name as PatientName 
    FROM Appointment a
    JOIN Doctor d ON a.DoctorID = d.DoctorID
    JOIN Patient p ON a.PatientID = p.PatientID
  `;
  connection.query(query, (err, results) => {
    if (err) throw err;
    res.render('menu3', { 
      appointments: results,
      userRole: req.session.userRole 
    });
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});