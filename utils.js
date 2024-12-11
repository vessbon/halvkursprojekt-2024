const fs = require('fs').promises;
const escape = require('escape-html');

async function getCredentials(body) {
    const regex = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/g

    let email = escape(body.email).toLowerCase();
    let password = escape(body.password);

    let match = email.match(regex);
    if (match == null) { return false; }

    return { email, password };
}

async function secureUploadData(body) {
    let title = escape(body.title);
    let allow_comments = body.comments;

    if (title.length > 3 && title.length < 50) {
        return { title, comments: allow_comments };
    } else {
        return false;
    }
}

async function parseJSON(fileName) {
    try {
        const data = await fs.readFile(fileName, 'utf-8');
        return JSON.parse(data);
    } catch (err) {
        console.log(err);
        return [];
    }
}

async function createUsernameFromEmail(email, existingUsers) {
    const regex = /([^@]+)/;
    const match = email.match(regex);

    let username = match[1]
    username = username ? username.replace(/([^a-zA-Z0-9])/, '') : new Error('Invalid email format.')
    username = username[0].toUpperCase() + username.slice(1);

    // Make sure it is unique
    let uniqueUsername = username;
    let suffix = 1;

    while (existingUsers.some(u => u.username.toLowerCase() === uniqueUsername.toLowerCase())) {
        uniqueUsername = `${username}${suffix}`
        suffix++;
    }

    return uniqueUsername;
}

async function generateWatchCode(uuid) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const id = await uuid.replace(/-/g, '');
    console.log(id);
    let result = '';

    result = await randomCharsFromString(id, 5) + await randomCharsFromString(characters, 5);
    return result;
}

async function randomCharsFromString(text, num) {
    let result = '';
    for (let i = 0; i < num; i++) {
        const randomChar = text.charAt(Math.floor(Math.random() * text.length));
        result += randomChar;
    }

    return result;
}

module.exports = { getCredentials, parseJSON, createUsernameFromEmail, secureUploadData, generateWatchCode };