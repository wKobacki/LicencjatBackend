const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const nodemailer = require('nodemailer');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT;

// Konfiguracja połączenia z bazą danych
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

db.connect((err) => {
    if (err) {
        console.error('Błąd połączenia z bazą danych:', err);
        return;
    }
    console.log('Połączono z bazą danych MySQL');
});

app.use(cors({
    origin: ['http://localhost', 'http://localhost:3000'],
    credentials: true
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

function parseImagesField(imagesField) {
    if (!imagesField) return [];
    if (Array.isArray(imagesField)) return imagesField;
    if (typeof imagesField === 'string') {
        // Jeśli to już jest JSON array
        if (imagesField.startsWith('[')) {
            try {
                const parsed = JSON.parse(imagesField);
                if (Array.isArray(parsed)) {
                    return parsed;
                } else if (typeof parsed === 'string') {
                    return [parsed];
                }
            } catch (e) {
                console.error('Błąd podczas parsowania JSON w images:', e);
            }
        }
        // Jeśli to pojedynczy string zaczynający się od '/uploads/'
        if (imagesField.startsWith('/uploads/')) {
            return [imagesField];
        }
    }
    return [];
}


// Konfiguracja przechowywania obrazów
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`);
    }
});

const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Niedozwolony typ pliku. Dozwolone są tylko obrazy w formacie jpg i png.'));
        }
    }
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Konfiguracja nodemailer
const transporter = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Middleware do uwierzytelniania użytkownika
function authenticateUser(req, res, next) {
    const userEmail = req.headers['x-user-email'];
    if (!userEmail) {
        return res.status(401).json({ message: 'Brak uwierzytelnienia' });
    }
    db.query('SELECT * FROM users WHERE email = ?', [userEmail], (err, results) => {
        if (err || results.length === 0) {
            return res.status(403).json({ message: 'Brak dostępu' });
        }
        req.user = results[0];
        next();
    });
}

// Middleware do autoryzacji admina
function authenticateAdmin(req, res, next) {
    const userEmail = req.headers['x-user-email'];
    if (!userEmail) {
        return res.status(401).json({ message: 'Brak uwierzytelnienia' });
    }
    db.query('SELECT * FROM users WHERE email = ?', [userEmail], (err, results) => {
        if (err || results.length === 0) {
            return res.status(403).json({ message: 'Brak dostępu' });
        }
        const user = results[0];
        if (user.role !== 'admin' && user.role !== 'manager') {
            return res.status(403).json({ message: 'Brak uprawnień' });
        }
        req.user = user;
        next();
    });
}

// Rejestracja nowego użytkownika z walidacją i hashowaniem hasła
app.post('/register',
    [
        body('email').isEmail().withMessage('Nieprawidłowy adres e-mail'),
        body('password').isLength({ min: 6 }).withMessage('Hasło musi mieć co najmniej 6 znaków'),
        body('name').notEmpty().withMessage('Imię jest wymagane'),
        body('surname').notEmpty().withMessage('Nazwisko jest wymagane'),
        body('branch').notEmpty().withMessage('Oddział jest wymagany'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: 'Błędne dane wejściowe', errors: errors.array() });
        }

        const { email, password, name, surname, branch } = req.body;

        try {
            const [existingUser] = await db.promise().query(
                'SELECT * FROM users WHERE email = ?',
                [email]
            );

            if (existingUser.length > 0) {
                return res.status(400).json({ message: 'E-mail jest już zarejestrowany.' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
            const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1h

            await db.promise().query(
                'INSERT INTO users (email, password, role, name, surname, branch, isVerified, isBlocked) VALUES (?, ?, "user", ?, ?, ?, false, false)',
                [email, hashedPassword, name, surname, branch]
            );

            await db.promise().query(
                'INSERT INTO verification_codes (email, code, expiresAt) VALUES (?, ?, ?)',
                [email, verificationCode, expiresAt]
            );

            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS,
                },
                tls: {
                    rejectUnauthorized: false
                }
            });

            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Zweryfikuj swój adres e-mail',
                text: `Twój kod weryfikacyjny to: ${verificationCode}. Kod jest ważny przez 1 godzinę.`
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.error('Błąd email:', error);
                    return res.status(500).json({ message: 'Błąd podczas wysyłania e-maila weryfikacyjnego.' });
                }
                return res.status(201).json({ message: 'Rejestracja zakończona. Sprawdź e-mail, aby się zweryfikować.' });
            });

        } catch (err) {
            console.error('Błąd rejestracji:', err);
            return res.status(500).json({ message: 'Błąd serwera podczas rejestracji.' });
        }
    });

// Weryfikacja kodu e-mail
app.post('/verify-email',
    [
        body('email').isEmail().withMessage('Nieprawidłowy adres e-mail'),
        body('code').isLength({ min: 6, max: 6 }).withMessage('Kod musi mieć 6 cyfr'),
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: 'Błędne dane wejściowe', errors: errors.array() });
        }

        const { email, code } = req.body;

        db.query('SELECT * FROM verification_codes WHERE email = ? AND code = ?', [email, code], (err, results) => {
            if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
            if (results.length === 0) return res.status(400).json({ message: 'Nieprawidłowy kod weryfikacyjny lub kod wygasł' });

            const { expiresAt } = results[0];
            if (new Date() > expiresAt) {
                db.query('DELETE FROM verification_codes WHERE email = ?', [email]);
                return res.status(400).json({ message: 'Kod weryfikacyjny wygasł.' });
            }

            db.query('UPDATE users SET isVerified = true WHERE email = ?', [email], (err) => {
                if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
                db.query('DELETE FROM verification_codes WHERE email = ?', [email]);
                res.status(200).json({ message: 'E-mail zweryfikowany pomyślnie.' });
            });
        });
    });

// Ponowne wysyłanie kodu weryfikacyjnego
app.post('/resend-verification-code',
    [
        body('email').isEmail().withMessage('Nieprawidłowy adres e-mail'),
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: 'Błędne dane wejściowe', errors: errors.array() });
        }

        const { email } = req.body;

        // Sprawdź, czy użytkownik istnieje i nie jest już zweryfikowany
        db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
            if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
            if (results.length === 0) return res.status(404).json({ message: 'Użytkownik nie znaleziony.' });

            const user = results[0];

            if (user.isVerified) {
                return res.status(400).json({ message: 'Użytkownik jest już zweryfikowany.' });
            }

            const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
            const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // Kod ważny przez 1 godzinę

            // Zapisz lub zaktualizuj kod weryfikacyjny w bazie danych
            db.query('INSERT INTO verification_codes (email, code, expiresAt) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE code = ?, expiresAt = ?',
                [email, verificationCode, expiresAt, verificationCode, expiresAt], (err) => {
                    if (err) return res.status(500).json({ message: 'Błąd bazy danych podczas generowania kodu' });

                    const mailOptions = {
                        from: process.env.EMAIL_USER,
                        to: email,
                        subject: 'Ponowne wysłanie kodu weryfikacyjnego',
                        text: `Twój nowy kod weryfikacyjny to: ${verificationCode}. Kod jest ważny przez 1 godzinę.`
                    };

                    transporter.sendMail(mailOptions, (error, info) => {
                        if (error) return res.status(500).json({ message: 'Błąd podczas wysyłania e-maila weryfikacyjnego.' });
                        res.status(200).json({ message: 'Kod weryfikacyjny został ponownie wysłany na Twój adres e-mail.' });
                    });
                });
        });
    });

// Logowanie użytkownika z weryfikacją hasła
app.post('/login',
    [
        body('email').isEmail().withMessage('Nieprawidłowy adres e-mail'),
        body('password').notEmpty().withMessage('Hasło jest wymagane'),
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: 'Błędne dane wejściowe', errors: errors.array() });
        }

        const { email, password } = req.body;

        db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
            if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
            if (results.length === 0) return res.status(401).json({ message: 'Nieprawidłowy e-mail lub hasło' });

            const user = results[0];

            const passwordMatch = await bcrypt.compare(password, user.password);
            if (!passwordMatch) return res.status(401).json({ message: 'Nieprawidłowy e-mail lub hasło' });

            if (!user.isVerified) return res.status(403).json({ message: 'Proszę zweryfikować adres e-mail, aby aktywować konto.' });

            res.status(200).json({ message: 'Logowanie zakończone sukcesem', user: { email: user.email, role: user.role, branch: user.branch } });
        });
    });

// Wysyłanie kodu resetu hasła
app.post('/forgot-password',
    [
        body('email').isEmail().withMessage('Nieprawidłowy adres e-mail'),
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: 'Błędne dane wejściowe', errors: errors.array() });
        }

        const { email } = req.body;

        db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
            if (err || results.length === 0) return res.status(404).json({ message: 'Użytkownik nie znaleziony.' });

            const code = Math.floor(100000 + Math.random() * 900000);
            const expiresAt = new Date(Date.now() + 3600000); // Ważność kodu: 1 godzina

            db.query('INSERT INTO reset_tokens (email, code, expiresAt) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE code = ?, expiresAt = ?',
                [email, code, expiresAt, code, expiresAt], (err) => {
                    if (err) return res.status(500).json({ message: 'Błąd bazy danych' });

                    const mailOptions = {
                        from: process.env.EMAIL_USER,
                        to: email,
                        subject: 'Kod resetu hasła',
                        text: `Twój kod do resetu hasła to: ${code}. Kod jest ważny przez 1 godzinę.`
                    };

                    transporter.sendMail(mailOptions, (error, info) => {
                        if (error) return res.status(500).json({ message: 'Błąd podczas wysyłania e-maila z kodem resetu hasła.' });
                        res.status(200).json({ message: 'Kod resetu hasła został wysłany na Twój adres e-mail.' });
                    });
                });
        });
    });

// Resetowanie hasła z walidacją i hashowaniem nowego hasła
app.post('/reset-password',
    [
        body('email').isEmail().withMessage('Nieprawidłowy adres e-mail'),
        body('code').isLength({ min: 6, max: 6 }).withMessage('Kod musi mieć 6 cyfr'),
        body('newPassword').isLength({ min: 6 }).withMessage('Nowe hasło musi mieć co najmniej 6 znaków'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: 'Błędne dane wejściowe', errors: errors.array() });
        }

        const { email, code, newPassword } = req.body;

        db.query('SELECT * FROM reset_tokens WHERE email = ? AND code = ?', [email, code], async (err, results) => {
            if (err || results.length === 0) return res.status(400).json({ message: 'Błędny kod weryfikacyjny.' });

            const token = results[0];
            if (new Date() > token.expiresAt) {
                db.query('DELETE FROM reset_tokens WHERE email = ?', [email]);
                return res.status(400).json({ message: 'Kod wygasł. Proszę spróbować ponownie.' });
            }

            const hashedPassword = await bcrypt.hash(newPassword, 10);

            db.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email], (err) => {
                if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
                db.query('DELETE FROM reset_tokens WHERE email = ?', [email]);
                res.status(200).json({ message: 'Hasło zostało zresetowane pomyślnie.' });
            });
        });
    });

// Zgłaszanie pomysłu z walidacją
app.post('/submitIdea', upload.array('images', 3), authenticateUser,
    [
        body('title').notEmpty().withMessage('Tytuł jest wymagany'),
        body('department').notEmpty().withMessage('Dział jest wymagany'),
        body('description').notEmpty().withMessage('Opis jest wymagany'),
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            // Usuń przesłane pliki w przypadku błędu walidacji
            if (req.files) {
                req.files.forEach(file => {
                    fs.unlinkSync(file.path);
                });
            }
            return res.status(400).json({ message: 'Błędne dane wejściowe', errors: errors.array() });
        }

        const { title, department, description, solution, branch } = req.body;
        const images = req.files ? req.files.map(file => `/uploads/${file.filename}`) : [];
        const userEmail = req.user.email;

        const user = req.user;
        if (user.isBlocked) {
            return res.status(403).json({ message: 'Nie masz uprawnień do dodawania pomysłów.' });
        }

        const sqlQuery = 'INSERT INTO ideas (title, department, description, solution, images, branch, status, votes, createdAt, author_email, isPublished, archived) VALUES (?, ?, ?, ?, ?, ?, "pending", 0, NOW(), ?, false, false)';
        const values = [title, department, description, solution, JSON.stringify(images), branch || user.branch, userEmail];

        db.query(sqlQuery, values, (err) => {
            if (err) {
                console.error('Błąd bazy danych podczas wstawiania pomysłu:', err);
                return res.status(500).json({ message: 'Błąd bazy danych podczas wstawiania pomysłu' });
            }
            res.status(201).json({ message: 'Pomysł dodany pomyślnie, oczekuje na akceptację przez admina.' });
        });
    });

// Zgłaszanie problemu z walidacją
app.post('/submitProblem', upload.array('images', 3), authenticateUser,
    [
        body('title').notEmpty().withMessage('Tytuł jest wymagany'),
        body('department').notEmpty().withMessage('Dział jest wymagany'),
        body('description').notEmpty().withMessage('Opis jest wymagany'),
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            // Usuń przesłane pliki w przypadku błędu walidacji
            if (req.files) {
                req.files.forEach(file => {
                    fs.unlinkSync(file.path);
                });
            }
            return res.status(400).json({ message: 'Błędne dane wejściowe', errors: errors.array() });
        }

        const { title, department, description, solution, branch } = req.body;
        const images = req.files ? req.files.map(file => `/uploads/${file.filename}`) : [];
        const userEmail = req.user.email;

        const user = req.user;
        if (user.isBlocked) {
            return res.status(403).json({ message: 'Nie masz uprawnień do dodawania problemów.' });
        }

        const sqlQuery = 'INSERT INTO problems (title, department, description, solution, images, branch, status, votes, createdAt, author_email, isPublished, archived) VALUES (?, ?, ?, ?, ?, ?, "pending", 0, NOW(), ?, false, false)';
        const values = [title, department, description, solution, JSON.stringify(images), branch || user.branch, userEmail];

        db.query(sqlQuery, values, (err) => {
            if (err) {
                console.error('Błąd bazy danych podczas wstawiania problemu:', err);
                return res.status(500).json({ message: 'Błąd bazy danych podczas wstawiania problemu' });
            }
            res.status(201).json({ message: 'Problem zgłoszony pomyślnie, oczekuje na akceptację przez admina.' });
        });
    });

// Pobieranie problemów
// Pobieranie problemów
app.get('/problems', authenticateUser, (req, res) => {
    const userEmail = req.user.email;
    const { status, archived, branch } = req.query;

    // Budowanie zapytania SQL na podstawie parametrów
    let sqlQuery = 'SELECT * FROM problems WHERE (isPublished = true OR status = "completed")';
    const queryParams = [];

    if (status) {
        const statuses = status.split(',');
        sqlQuery += ` AND status IN (${statuses.map(() => '?').join(',')})`;
        queryParams.push(...statuses);
    }

    if (archived) {
        sqlQuery += ' AND archived = ?';
        queryParams.push(archived === 'true');
    }

    if (branch) {
        sqlQuery += ' AND branch = ?';
        queryParams.push(branch);
    }

    db.query(sqlQuery, queryParams, (err, results) => {
        if (err) {
            console.error('Błąd bazy danych:', err);
            return res.status(500).json({ message: 'Błąd bazy danych' });
        }

        // Pobierz identyfikatory problemów
        const problemIds = results.map((problem) => problem.id);

        if (problemIds.length > 0) {
            // Pobierz listę problemów, na które użytkownik zagłosował
            db.query(
                'SELECT item_id FROM user_votes WHERE user_email = ? AND item_type = "problem" AND item_id IN (?)',
                [userEmail, problemIds],
                (err, voteResults) => {
                    if (err) {
                        console.error('Błąd bazy danych:', err);
                        return res.status(500).json({ message: 'Błąd bazy danych' });
                    }

                    const votedProblemIds = voteResults.map((vote) => vote.item_id);

                    // Przetwórz problemy i dodaj pole hasVoted
                    const problems = results.map((problem) => {
                        const images = parseImagesField(problem.images);
                        const hasVoted = votedProblemIds.includes(problem.id);
                        return { ...problem, images, hasVoted };
                    });

                    // Pobierz łączną liczbę głosów użytkownika na problemy w statusie 'in_voting'
                    db.query(
                        'SELECT COUNT(*) AS voteCount FROM user_votes JOIN problems ON user_votes.item_id = problems.id WHERE user_votes.user_email = ? AND user_votes.item_type = "problem" AND problems.status = "in_voting"',
                        [userEmail],
                        (err, voteCountResult) => {
                            if (err) {
                                console.error('Błąd bazy danych:', err);
                                return res.status(500).json({ message: 'Błąd bazy danych' });
                            }

                            const voteCount = voteCountResult[0].voteCount;

                            res.json({
                                problems,
                                userVoteCount: voteCount,
                            });
                        }
                    );
                }
            );
        } else {
            // Jeśli problemIds jest puste, zwróć pustą listę głosów
            res.json({
                problems: results.map(problem => ({ ...problem, hasVoted: false })), // wszystkie problemy bez głosów
                userVoteCount: 0,
            });
        }
    });
});

// pobieranie pomysłów
app.get('/ideas', authenticateUser, (req, res) => {
    const userEmail = req.user.email;
    const { status, archived, branch } = req.query;

    // Budowanie zapytania SQL na podstawie parametrów
    let sqlQuery = 'SELECT * FROM ideas WHERE (isPublished = true OR status = "completed")';
    const queryParams = [];

    if (status) {
        const statuses = status.split(',');
        sqlQuery += ` AND status IN (${statuses.map(() => '?').join(',')})`;
        queryParams.push(...statuses);
    }

    if (archived) {
        sqlQuery += ' AND archived = ?';
        queryParams.push(archived === 'true');
    }

    if (branch) {
        sqlQuery += ' AND branch = ?';
        queryParams.push(branch);
    }

    db.query(sqlQuery, queryParams, (err, results) => {
        if (err) {
            console.error('Błąd bazy danych:', err);
            return res.status(500).json({ message: 'Błąd bazy danych' });
        }

        // Pobierz identyfikatory pomysłów
        const ideaIds = results.map(idea => idea.id);

        if (ideaIds.length > 0) {
            // Pobierz listę pomysłów, na które użytkownik zagłosował
            db.query(
                'SELECT item_id FROM user_votes WHERE user_email = ? AND item_type = "idea" AND item_id IN (?)',
                [userEmail, ideaIds],
                (err, voteResults) => {
                    if (err) {
                        console.error('Błąd bazy danych:', err);
                        return res.status(500).json({ message: 'Błąd bazy danych' });
                    }

                    const votedIdeaIds = voteResults.map(vote => vote.item_id);

                    const ideas = results.map(idea => {
                        const images = parseImagesField(idea.images);
                        const hasVoted = votedIdeaIds.includes(idea.id);
                        return { ...idea, images, hasVoted };
                    });

                    // Pobierz łączną liczbę głosów użytkownika na pomysły w statusie 'in_voting'
                    db.query(
                        'SELECT COUNT(*) AS voteCount FROM user_votes JOIN ideas ON user_votes.item_id = ideas.id WHERE user_votes.user_email = ? AND user_votes.item_type = "idea" AND ideas.status = "in_voting"',
                        [userEmail],
                        (err, voteCountResult) => {
                            if (err) {
                                console.error('Błąd bazy danych:', err);
                                return res.status(500).json({ message: 'Błąd bazy danych' });
                            }

                            const voteCount = voteCountResult[0].voteCount;

                            res.json({
                                ideas,
                                userVoteCount: voteCount,
                            });
                        }
                    );
                }
            );
        } else {
            // Jeśli ideaIds jest puste, zwróć pustą listę głosów
            res.json({
                ideas: results.map(idea => ({ ...idea, hasVoted: false })), // wszystkie pomysły bez głosów
                userVoteCount: 0,
            });
        }
    });
});

// Głosowanie na problem
app.post('/problems/:id/vote', authenticateUser, (req, res) => {
    const problemId = parseInt(req.params.id);
    const userEmail = req.user.email;

    // Sprawdź, czy problem istnieje i pobierz jego dane
    db.query('SELECT * FROM problems WHERE id = ?', [problemId], (err, problemResults) => {
        if (err || problemResults.length === 0) {
            return res.status(404).json({ message: 'Problem nie znaleziony' });
        }

        const problem = problemResults[0];

        // Sprawdź, czy użytkownik nie próbuje głosować na swój własny problem
        if (problem.author_email === userEmail) {
            return res.status(400).json({ message: 'Nie możesz głosować na swój własny problem' });
        }

        // Sprawdź, czy problem jest w statusie 'in_voting'
        if (problem.status !== 'in_voting') {
            return res.status(400).json({ message: 'Głosowanie jest zamknięte dla tego problemu' });
        }

        // Sprawdź, czy użytkownik już głosował na ten problem
        db.query(
            'SELECT * FROM user_votes WHERE user_email = ? AND item_id = ? AND item_type = "problem"',
            [userEmail, problemId],
            (err, voteResults) => {
                if (err) {
                    console.error('Błąd bazy danych:', err);
                    return res.status(500).json({ message: 'Błąd bazy danych' });
                }

                if (voteResults.length > 0) {
                    // Użytkownik już głosował na ten problem, więc cofnij głos
                    db.query(
                        'DELETE FROM user_votes WHERE user_email = ? AND item_id = ? AND item_type = "problem"',
                        [userEmail, problemId],
                        (err) => {
                            if (err) {
                                console.error('Błąd bazy danych:', err);
                                return res.status(500).json({ message: 'Błąd bazy danych' });
                            }

                            // Zmniejsz liczbę głosów na problemie
                            db.query('UPDATE problems SET votes = votes - 1 WHERE id = ?', [problemId], (err) => {
                                if (err) {
                                    console.error('Błąd bazy danych:', err);
                                    return res.status(500).json({ message: 'Błąd bazy danych' });
                                }

                                res.status(200).json({ message: 'Głos cofnięty' });
                            });
                        }
                    );
                } else {
                    // Użytkownik nie głosował jeszcze na ten problem, sprawdź limit głosów
                    db.query(
                        'SELECT COUNT(*) AS voteCount FROM user_votes JOIN problems ON user_votes.item_id = problems.id WHERE user_votes.user_email = ? AND user_votes.item_type = "problem" AND problems.status = "in_voting"',
                        [userEmail],
                        (err, voteCountResult) => {
                            if (err) {
                                console.error('Błąd bazy danych:', err);
                                return res.status(500).json({ message: 'Błąd bazy danych' });
                            }

                            const voteCount = voteCountResult[0].voteCount;

                            if (voteCount >= 3) {
                                return res.status(400).json({ message: 'Osiągnąłeś limit 3 głosów na problemy' });
                            }

                            // Dodaj głos
                            db.query(
                                'INSERT INTO user_votes (user_email, item_id, item_type) VALUES (?, ?, "problem")',
                                [userEmail, problemId],
                                (err) => {
                                    if (err) {
                                        console.error('Błąd bazy danych:', err);
                                        return res.status(500).json({ message: 'Błąd bazy danych' });
                                    }

                                    // Zwiększ liczbę głosów na problemie
                                    db.query('UPDATE problems SET votes = votes + 1 WHERE id = ?', [problemId], (err) => {
                                        if (err) {
                                            console.error('Błąd bazy danych:', err);
                                            return res.status(500).json({ message: 'Błąd bazy danych' });
                                        }

                                        res.status(200).json({ message: 'Głos dodany' });
                                    });
                                }
                            );
                        }
                    );
                }
            }
        );
    });
});

// Głosowanie na pomysł
app.post('/ideas/:id/vote', authenticateUser, (req, res) => {
    const ideaId = parseInt(req.params.id);
    const userEmail = req.user.email;

    // Sprawdź, czy użytkownik próbuje głosować na swój własny pomysł
    db.query('SELECT * FROM ideas WHERE id = ?', [ideaId], (err, ideaResults) => {
        if (err || ideaResults.length === 0) return res.status(404).json({ message: 'Pomysł nie znaleziony' });

        const idea = ideaResults[0];

        if (idea.author_email === userEmail) {
            return res.status(400).json({ message: 'Nie możesz głosować na swój własny pomysł' });
        }

        // Sprawdź, ile głosów użytkownik oddał na pomysły
        db.query('SELECT COUNT(*) AS voteCount FROM user_votes WHERE user_email = ? AND item_type = "idea"', [userEmail], (err, voteCountResults) => {
            if (err) return res.status(500).json({ message: 'Błąd bazy danych' });

            const voteCount = voteCountResults[0].voteCount;

            // Sprawdź, czy użytkownik już głosował na ten pomysł
            db.query('SELECT * FROM user_votes WHERE user_email = ? AND item_id = ? AND item_type = "idea"', [userEmail, ideaId], (err, results) => {
                if (err) return res.status(500).json({ message: 'Błąd bazy danych' });

                if (results.length > 0) {
                    // Cofnięcie głosu
                    db.query('DELETE FROM user_votes WHERE user_email = ? AND item_id = ? AND item_type = "idea"', [userEmail, ideaId], (err) => {
                        if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
                        db.query('UPDATE ideas SET votes = votes - 1 WHERE id = ?', [ideaId], (err) => {
                            if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
                            res.status(200).json({ message: 'Głos cofnięty' });
                        });
                    });
                } else {
                    // Sprawdź, czy użytkownik osiągnął limit głosów
                    if (voteCount >= 1) {
                        return res.status(400).json({ message: 'Osiągnąłeś limit 1 głosu na pomysły' });
                    }

                    // Dodanie głosu
                    db.query('INSERT INTO user_votes (user_email, item_id, item_type) VALUES (?, ?, "idea")', [userEmail, ideaId], (err) => {
                        if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
                        db.query('UPDATE ideas SET votes = votes + 1 WHERE id = ?', [ideaId], (err) => {
                            if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
                            res.status(200).json({ message: 'Głos dodany' });
                        });
                    });
                }
            });
        });
    });
});

// Pobieranie pomysłów i problemów do zarządzania przez admina
app.get('/admin/ideas', authenticateAdmin, (req, res) => {
    const { archived } = req.query;

    // Initialize the base queries
    let sqlQueryIdeas = 'SELECT * FROM ideas';
    let sqlQueryProblems = 'SELECT * FROM problems';

    // Arrays to hold conditions and parameters
    const ideaConditions = [];
    const problemConditions = [];
    const ideaQueryParams = [];
    const problemQueryParams = [];

    // Handle the 'archived' parameter
    if (archived) {
        ideaConditions.push('archived = ?');
        problemConditions.push('archived = ?');
        const archivedValue = archived === 'true';
        ideaQueryParams.push(archivedValue);
        problemQueryParams.push(archivedValue);
    } else {
        // Default to 'archived = false' if not specified
        ideaConditions.push('archived = ?');
        problemConditions.push('archived = ?');
        ideaQueryParams.push(false);
        problemQueryParams.push(false);
    }

    // Build the WHERE clauses if there are conditions
    if (ideaConditions.length > 0) {
        sqlQueryIdeas += ' WHERE ' + ideaConditions.join(' AND ');
    }

    if (problemConditions.length > 0) {
        sqlQueryProblems += ' WHERE ' + problemConditions.join(' AND ');
    }

    // Fetch ideas
    db.query(sqlQueryIdeas, ideaQueryParams, (err, ideas) => {
        if (err) {
            console.error('Database error while fetching ideas:', err);
            return res.status(500).json({ message: 'Database error' });
        }

        // Parse images in ideas
        const parsedIdeas = ideas.map(idea => {
            const images = parseImagesField(idea.images);
            return { ...idea, images, type: 'idea' };
        });

        // Fetch problems
        db.query(sqlQueryProblems, problemQueryParams, (err, problems) => {
            if (err) {
                console.error('Database error while fetching problems:', err);
                return res.status(500).json({ message: 'Database error' });
            }

            // Parse images in problems
            const parsedProblems = problems.map(problem => {
                const images = parseImagesField(problem.images);
                return { ...problem, images, type: 'problem' };
            });

            // Combine and send the data
            const combinedData = [...parsedIdeas, ...parsedProblems];
            res.json(combinedData);
        });
    });
});

// Aktualizacja statusu pomysłu lub problemu
app.put('/admin/:type/:id/status', authenticateAdmin, (req, res) => {
    const itemId = parseInt(req.params.id);
    const { status } = req.body;
    const type = req.params.type;

    // Lista dozwolonych statusów bez "rejected"
    const allowedStatuses = ['pending', 'in_voting', 'in_progress', 'completed'];

    if (!['ideas', 'problems'].includes(type)) {
        return res.status(400).json({ message: 'Nieprawidłowy typ elementu' });
    }

    // Sprawdzamy, czy status jest dozwolony
    if (!allowedStatuses.includes(status)) {
        return res.status(400).json({ message: 'Nieprawidłowy status elementu' });
    }

    const table = type === 'ideas' ? 'ideas' : 'problems';

    // Ustawiamy isPublished na true dla "in_voting" i "in_progress" (lub innej logiki, jeśli trzeba)
    const isPublished = (status === 'in_voting' || status === 'in_progress');

    db.query(`UPDATE ${table} SET status = ?, isPublished = ? WHERE id = ?`, [status, isPublished, itemId], (err) => {
        if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
        res.status(200).json({ message: 'Status elementu zaktualizowany' });
    });
});

// Usuwanie elementu (problemu)
app.delete('/admin/problems/:id', authenticateAdmin, (req, res) => {
    const problemId = parseInt(req.params.id, 10);
    if (isNaN(problemId) || problemId <= 0) {
        return res.status(400).json({ message: 'Invalid ID format' });
    }

    db.query('DELETE FROM problems WHERE id = ?', [problemId], (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ message: 'Database error' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Problem not found' });
        }

        res.status(200).json({ message: 'Problem deleted successfully' });
    });
});

// Usuwanie elementu (pomysłu)
app.delete('/admin/ideas/:id', authenticateAdmin, (req, res) => {
    const ideaId = parseInt(req.params.id, 10);
    console.log(`Received request to delete idea with ID: ${ideaId}`);

    if (isNaN(ideaId) || ideaId <= 0) {
        console.error(`Invalid ID format: ${req.params.id}`);
        return res.status(400).json({ message: 'Invalid ID format' });
    }

    db.query('DELETE FROM ideas WHERE id = ?', [ideaId], (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ message: 'Database error' });
        }

        if (result.affectedRows === 0) {
            console.warn(`No idea found with ID: ${ideaId}`);
            return res.status(404).json({ message: 'Idea not found' });
        }

        console.log(`Idea with ID: ${ideaId} deleted successfully.`);
        return res.status(200).json({ message: 'Idea deleted successfully' });
    });
});

// Archiwizacja elementu
app.put('/admin/:type/:id/archive', authenticateAdmin, (req, res) => {
    const itemId = parseInt(req.params.id);
    const { archived } = req.body;
    const type = req.params.type;

    if (!['ideas', 'problems'].includes(type)) {
        return res.status(400).json({ message: 'Nieprawidłowy typ elementu' });
    }

    const table = type === 'ideas' ? 'ideas' : 'problems';
    db.query(`UPDATE ${table} SET archived = ? WHERE id = ?`, [archived, itemId], (err) => {
        if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
        res.json({ message: 'Archiwizacja elementu zakończona pomyślnie' });
    });
});

// Aktualizacja roli użytkownika
app.put('/admin/users/:id/role', authenticateAdmin, (req, res) => {
    const userId = parseInt(req.params.id);
    const { role } = req.body;

    db.query('UPDATE users SET role = ? WHERE id = ?', [role, userId], (err) => {
        if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
        res.status(200).json({ message: 'Rola użytkownika zaktualizowana pomyślnie' });
    });
});

// Zmiana oddziału użytkownika
app.put('/admin/users/:id/branch', authenticateAdmin, (req, res) => {
    const userId = parseInt(req.params.id);
    const { branch } = req.body;

    db.query('UPDATE users SET branch = ? WHERE id = ?', [branch, userId], (err) => {
        if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
        res.status(200).json({ message: 'Oddział użytkownika zaktualizowany pomyślnie' });
    });
});

// Blokowanie lub odblokowywanie użytkownika
app.put('/admin/users/:id/block', authenticateAdmin, (req, res) => {
    const userId = parseInt(req.params.id);
    const { isBlocked } = req.body;

    db.query('UPDATE users SET isBlocked = ? WHERE id = ?', [isBlocked, userId], (err) => {
        if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
        res.status(200).json({ message: isBlocked ? 'Użytkownik zablokowany' : 'Użytkownik odblokowany' });
    });
});

//usuwanie użytkowników
app.delete('/admin/users/:id', authenticateAdmin, (req, res) => {
    const userId = parseInt(req.params.id, 10);
    console.log(`Received request to delete user with ID: ${userId}, Type: ${typeof userId}`);

    // Sprawdzenie, czy ID jest poprawne
    if (isNaN(userId) || userId <= 0) {
        console.error(`Invalid ID format: ${req.params.id}`);
        return res.status(400).json({ message: 'Invalid ID format' });
    }

    db.query('DELETE FROM users WHERE id = ?', [userId], (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ message: 'Database error' });
        }

        if (result.affectedRows === 0) {
            console.warn(`No user found with ID: ${userId}`);
            return res.status(404).json({ message: 'User not found' });
        }

        console.log(`User with ID: ${userId} deleted successfully.`);
        return res.status(200).json({ message: 'User deleted successfully' });
    });
});

// Pobieranie użytkowników
app.get('/admin/users', authenticateAdmin, (req, res) => {
    db.query('SELECT id, email, role, name, surname, branch, isVerified, isBlocked FROM users', (err, results) => {
        if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
        res.status(200).json(results);
    });
});

// Resetowanie głosów dla wszystkich użytkowników
app.put('/admin/users/reset_votes', authenticateAdmin, (req, res) => {
    db.query('DELETE FROM user_votes', (err) => {
        if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
        db.query('UPDATE problems SET votes = 0', (err) => {
            if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
            db.query('UPDATE ideas SET votes = 0', (err) => {
                if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
                res.status(200).json({ message: 'Głosy wszystkich użytkowników zostały zresetowane.' });
            });
        });
    });
});

// Zmiana hasła z walidacją i hashowaniem nowego hasła
app.post('/changePassword', authenticateUser,
    [
        body('oldPassword').notEmpty().withMessage('Stare hasło jest wymagane'),
        body('newPassword').isLength({ min: 6 }).withMessage('Nowe hasło musi mieć co najmniej 6 znaków'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: 'Błędne dane wejściowe', errors: errors.array() });
        }

        const { oldPassword, newPassword } = req.body;
        const email = req.user.email;

        db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
            if (err || results.length === 0) return res.status(404).json({ message: 'Użytkownik nie znaleziony' });

            const user = results[0];

            const passwordMatch = await bcrypt.compare(oldPassword, user.password);
            if (!passwordMatch) return res.status(401).json({ message: 'Stare hasło jest nieprawidłowe' });

            const hashedPassword = await bcrypt.hash(newPassword, 10);

            db.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email], (err) => {
                if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
                res.status(200).json({ message: 'Hasło zostało zmienione pomyślnie' });
            });
        });
    });

// Sprawdzanie statusu użytkownika (czy jest zablokowany)
app.get('/admin/users/status', authenticateUser, (req, res) => {
    const userEmail = req.user.email;
    db.query('SELECT isBlocked FROM users WHERE email = ?', [userEmail], (err, results) => {
        if (err || results.length === 0) return res.status(404).json({ message: 'Użytkownik nie znaleziony.' });
        res.status(200).json({ isBlocked: results[0].isBlocked });
    });
});

// Dodanie komentarza
app.post('/comments', authenticateUser, (req, res) => {
    const { item_id, item_type, parent_id, content } = req.body;
    const author_email = req.user.email;

    if (!item_id || !item_type || !content) {
        return res.status(400).json({ message: 'Brakuje wymaganych danych' });
    }

    const sql = 'INSERT INTO comments (item_id, item_type, parent_id, author_email, content) VALUES (?, ?, ?, ?, ?)';
    db.query(sql, [item_id, item_type, parent_id || null, author_email, content], (err) => {
        if (err) return res.status(500).json({ message: 'Błąd bazy danych' });
        res.status(201).json({ message: 'Komentarz dodany pomyślnie' });
    });
});

// Pobieranie komentarzy (zagnieżdżone)
app.get('/comments', authenticateUser, (req, res) => {
    const { item_id, item_type } = req.query;

    if (!item_id || !item_type) {
        return res.status(400).json({ message: 'Brakuje parametrów zapytania' });
    }

    const sql = 'SELECT * FROM comments WHERE item_id = ? AND item_type = ? ORDER BY created_at ASC';
    db.query(sql, [item_id, item_type], (err, results) => {
        if (err) return res.status(500).json({ message: 'Błąd bazy danych' });

        const nestComments = (comments, parentId = null) =>
            comments
                .filter(c => c.parent_id === parentId)
                .map(c => ({
                    ...c,
                    replies: nestComments(comments, c.id)
                }));

        res.json(nestComments(results));
    });
});

app.post('/comments/:id/like', (req, res) => {
    const commentId = req.params.id;
    const userEmail = req.headers['x-user-email'];

    if (!userEmail) return res.status(401).json({ message: 'Brak e-maila użytkownika.' });

    const checkQuery = 'SELECT * FROM comment_likes WHERE comment_id = ? AND user_email = ?';
    db.query(checkQuery, [commentId, userEmail], (err, result) => {
        if (err) return res.status(500).json({ message: 'Błąd bazy danych.' });

        if (result.length > 0) {
            return res.status(400).json({ message: 'Już polubiłeś ten komentarz.' });
        }

        const insertQuery = 'INSERT INTO comment_likes (comment_id, user_email) VALUES (?, ?)';
        db.query(insertQuery, [commentId, userEmail], (err2) => {
            if (err2) return res.status(500).json({ message: 'Błąd zapisu polubienia.' });

            const updateLikes = 'UPDATE comments SET likes = likes + 1 WHERE id = ?';
            db.query(updateLikes, [commentId], (err3) => {
                if (err3) return res.status(500).json({ message: 'Błąd aktualizacji liczby polubień.' });

                return res.status(200).json({ message: 'Polubiono komentarz.' });
            });
        });
    });
});

// Wylogowanie użytkownika
app.post('/logout', authenticateUser, (req, res) => {
    res.status(200).json({ message: 'Wylogowano pomyślnie' });
});

// Uruchomienie serwera
app.listen(PORT, () => {
    console.log(`Serwer działa na porcie ${PORT}`);
});
