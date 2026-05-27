// Vulnerable JavaScript frontend
const express = require('express');
const app = express();

// !! HIGH: XSS via innerHTML
function renderSearchResults(query) {
  const results = document.getElementById('results');
  results.innerHTML = 'Results for: ' + query;  // XSS!
}

// !! HIGH: XSS via dangerouslySetInnerHTML (React pattern)
function UserProfile({ bio }) {
  return React.createElement('div', {
    dangerouslySetInnerHTML: { __html: bio }
  });
}

// !! HIGH: SQL Injection in Node.js
const mysql = require('mysql');
const db = mysql.createConnection({ host: 'localhost', database: 'mydb' });

function getUser(userId) {
  db.query(`SELECT * FROM users WHERE id = ${userId}`, (err, result) => {
    // XSS: reflecting user input back
    res.send('<html>User: ' + req.query.name + '</html>');
  });
}

// !! HIGH: Weak crypto
const crypto = require('crypto');
function hashPassword(pwd) {
  return crypto.createHash('md5').update(pwd).digest('hex');
}

// !! MEDIUM: eval() with user input
function processInput(userCode) {
  return eval(userCode);  // dangerous!
}

// !! HIGH: Hardcoded API key
const SLACK_TOKEN = "xoxb-" + "123456789012" + "-ABCDEFabcdef123456789";
const GITHUB_TOKEN = "ghp_" + "1234567890ABCDEFabcdefGHIJKL123456";

app.listen(3000);
