// Dependencies
const { getCredentials, parseJSON, createUsernameFromEmail, secureUploadData, generateWatchCode } = require('./utils.js')
const fs = require('fs').promises;
const path = require('path');
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const ffmpeg = require('fluent-ffmpeg');
const ffprobe = require('ffprobe-static');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');

// Constants
const app = express();

const PORT = 3306;
const SALT_ROUNDS = 10;

const dateOptions = {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
};

const allowedMimeTypes = [
    'video/mp4',
    'video/webm',
    'video/ogg'
]

const videoExtensions = [
    '.mp4',
    '.webm',
    '.ogg'
];


app.listen(PORT, _ => console.log(`https://localhost:${PORT}`));

app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: '4AU7LEXT098Y',
    resave: false,
    saveUninitialized: false,
    cookie: {
        // Session lasts one day
        maxAge: 24 * 60 * 60 * 1000,
        secure: false
    }
}))

// Setup ffprobe for ffmpeg (thumbnails)
ffmpeg.setFfprobePath(ffprobe.path);

// Multer setup
const fileStorageEngine = multer.diskStorage({
    destination: async function (req, res, cb) {
        const watchCode = await generateWatchCode(req.session.userId)
        const uploadPath = `public/uploads/${req.session.userId}/${watchCode}`;

        req.watchCode = watchCode;

        try {
            // Check if the folder exists, if it doesn't => create it
            await fs.mkdir(uploadPath, { recursive: true });

            // Proceed with destination callback
            cb(null, uploadPath);

        } catch (err) {
            cb(err);
        }
    },
    filename: function (req, file, cb) {
        const extension = path.extname(file.originalname).toLowerCase();
        cb(null, file.fieldname + extension);
    }
});

const upload = multer({
    storage: fileStorageEngine,
    fileFilter: (req, file, cb) => {
        if (allowedMimeTypes.includes(file.mimetype)) {
            cb(null, true)
        } else {
            cb(new Error('Invalid file type.'))
        }
    }
})

app.get('/', index);
app.get('/login', login);
app.get('/register', register);
app.get('/channel', requireAuth, redirectToChannel);
app.get('/channel/:uuid', requireAuth, uploadPage);
app.get('/watch/:code')

app.post('/login', loginHandler);
app.post('/register', registrationHandler);
app.post('/channel/:uuid', requireAuth, upload.single('video'), uploadSingle);


async function index(req, res) {
    try {
        if (req.session.auth) {
            let videos = await parseJSON('data/videos.json');

            const videoElements = videos.map(video => {
                const videoPath = path.join(video.path, video.filename);
                const thumbnailPath = path.join(video.path, video.thumbnail);
                const fileExtension = path.extname(video.filename).toLowerCase();

                if (videoExtensions.includes(fileExtension)) {
                    return `<div class="thumbnail-container">
                            <a href="/watch/${video.watch_code}">
                                <img src="/${thumbnailPath}" alt="Thumbnail for the video."></img>
                            </a>
                            <p>${video.title}</p>
                            <p>Uploaded on ${new Date(video.date).toLocaleDateString('en-EN', dateOptions)} <strong>By ${video.username}</strong></p>
                        </div>`;
                } else {
                    return `<p>Unsupported file type: ${video.filename}</p>`;
                }
            }).join('') // Adds upp all the video html as one string

            const content = `
            <div class="video-gallery">
                    ${videoElements || '<p>No videos uploaded yet.</p>'}
            </div>
            `
            return res.send(await renderHtml(content));
        }

        // Send the default HTML file if user is not authenticated
        res.sendFile(__dirname + '/html/template.html');

    } catch (err) {
        console.log(err);
        res.status(500).send({ error: 'Failed to load page.' });
    }
}

function login(req, res) {
    res.sendFile(__dirname + '/html/login.html');
}

function register(req, res) {
    res.sendFile(__dirname + '/html/register.html');
}

function uploadPage(req, res) {
    res.sendFile(__dirname + '/html/upload.html')
}

async function loginHandler(req, res) {
    try {
        let users = await parseJSON('data/users.json');
        let credentials = await getCredentials(req.body);

        if (!credentials) { return res.redirect('back'); }

        const user = users.find(u => u.email === credentials.email);

        if (user) {
            let hasedPassword = user.password;
            let isMatch = await bcrypt.compare(credentials.password, hasedPassword);
            if (isMatch) {
                req.session.auth = true;
                req.session.userId = user.userId;
                req.session.email = user.email;
                req.session.username = user.username;
                res.redirect('/');

            } else {
                return res.send("Incorrect credentials.")
            }

        } else {
            return res.send("Could not find user.")
        }

    } catch (err) {
        console.log(err);
        res.status(500).send({ error: 'Login failed.' });
    }
}

async function registrationHandler(req, res) {
    try {
        let users = await parseJSON('data/users.json');
        let credentials = await getCredentials(req.body);

        if (!credentials) { return res.redirect('back'); }

        // Initialize user JSON structure with UUID (128-bit identifier)
        credentials.userId = uuidv4();

        if (users.find(u => u.email === credentials.email)) {
            return res.send({ message: 'Email already exists.' });
        } else if (users.find(u => u.userId === credentials.userId)) {
            credentials.userId = uuidv4(); // Tries again
        }

        const salt = await bcrypt.genSalt(SALT_ROUNDS);
        credentials.password = await bcrypt.hash(credentials.password, salt);
        credentials.username = await createUsernameFromEmail(credentials.email, users);
        credentials.usernameLastChanged = false;

        users.push(credentials);
        await fs.writeFile('data/users.json', JSON.stringify(users, null, 4));

        res.status(201).send({ message: 'User registered successfully.' });

    } catch (err) {
        console.log(err);
        res.status(500).send({ error: 'Registration failed.' });
    }
}

async function uploadSingle(req, res) {
    if (!req.session.auth) {
        return res.status(401).send({ message: 'Unauthorized.' });
    }

    try {
        const file = req.file;
        if (!file) {
            return res.status(400).send({ message: 'No file uploaded' });
        }

        const info = await secureUploadData(req.body);
        if (!info) {
            await fs.unlink(path.join(file.destination, file.filename));
            return res.status(400).send({ message: 'Invalid video information provided.' });
        }

        // Ensure the uploaded file type is supported
        const fileExtension = path.extname(file.originalname).toLowerCase();

        if (!videoExtensions.includes(fileExtension)) {
            return res.status(400).send({ message: 'Invalid file type.' });
        }

        // Convert unsupported file types to mp4 using ffmpeg (TO-DO)
        // let convertedFilename = file.filename;

        // Thumbnail save path
        const thumbnailFilename = `thumbnail-${Math.round(Math.random() * 1E5)}.jpg`
        const thumbnailPath = path.join(file.destination, thumbnailFilename);

        // Generate thumbnail
        await new Promise((resolve, reject) => {
            ffmpeg(path.join(file.destination, file.filename))
                .on('end', resolve)
                .on('error', reject)
                .screenshot({
                    count: 1,
                    folder: file.destination,
                    filename: thumbnailFilename,
                    size: '320x240'
                })
        })

        // Define JSON structure
        const newVideoEntry = {
            id: req.session.userId,
            username: req.session.username,
            title: info.title,
            path: file.destination.replace('public/', ''),
            thumbnail: thumbnailFilename,
            filename: file.filename,
            date: new Date().toISOString(),
            watch_code: req.watchCode,
            allow_comments: info.comments
        }

        // Load existing JSON data
        let videos = await parseJSON('data/videos.json');

        // Add video entry to JSON structure
        videos.push(newVideoEntry);
        await fs.writeFile('data/videos.json', JSON.stringify(videos, null, 4));

        res.status(201).send({ message: 'File uploaded successfully' });

    } catch (err) {
        console.log(err);
        res.status(500).send({ message: 'File upload failed.' });
    }
}

async function redirectToChannel(req, res) {
    try {
        res.redirect(`/channel/${req.session.userId}`);
    } catch (err) {
        console.log(err);
        res.status(499).send({ message: 'Incorrect channel uuid.' });
    }
}

function requireAuth(req, res, next) {
    if (req.session.auth) {
        next();
    } else {
        res.redirect('/login');
    }
}

async function renderHtml(content, replaceKeyword = '{content}', fileName = 'html/auth_template.html') {

    let text = await fs.readFile(fileName, 'utf-8');
    text = text.replace(replaceKeyword, content)
    return text;
}
