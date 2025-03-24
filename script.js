async function checkPassword() {
    const password = document.getElementById('passwordInput').value;
    const resultElement = document.getElementById('result');

    // Clear previous result
    resultElement.textContent = '';

    // Check NIST standards
    if (!isValidPassword(password)) {
        resultElement.textContent = "Password does not meet NIST standards. It must be at least 12 characters long, include upper and lower case letters, numbers, special characters, and no repeating patterns.";
        resultElement.style.color = 'red';
        return;
    }

    // Check if password has been pwned
    try {
        const pwnedCount = await checkPasswordPwned(password);
        if (pwnedCount > 0) {
            resultElement.textContent = `Your password has been pwned ${pwnedCount} times! Consider changing it.`;
            resultElement.style.color = 'red';
        } else {
            resultElement.textContent = 'Your password has not been pwned and complies with NIST Standards.';
            resultElement.style.color = 'green';
        }
    } catch (error) {
        resultElement.textContent = 'Error checking if password was pwned. Please try again later.';
        resultElement.style.color = 'orange';
    }
}

function isValidPassword(password) {
    // NIST Guidelines Check
    if (password.length < 12) return false;
    if (!/[A-Z]/.test(password)) return false; // Uppercase
    if (!/[a-z]/.test(password)) return false; // Lowercase
    if (!/[0-9]/.test(password)) return false; // Digit
    if (!/[!@#$%^&*()_+{}":;'<>?,./]/.test(password)) return false; // Special char
    if (hasRepeatingPatterns(password)) return false;

    return true;
}

function hasRepeatingPatterns(password) {
    // Check for three or more consecutive identical characters
    for (let i = 0; i < password.length - 2; i++) {
        if (password[i] === password[i + 1] && password[i] === password[i + 2]) {
            return true;
        }
    }

    // Check for repeating sequences
    for (let i = 1; i <= password.length / 2; i++) {
        const sequence = password.slice(0, i);
        if (password.includes(sequence.repeat(2))) {
            return true;
        }
    }

    return false;
}

async function checkPasswordPwned(password) {
    // Hash the password with SHA-1 using Web Crypto API
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const sha1Hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

    const prefix = sha1Hash.slice(0, 5);
    const suffix = sha1Hash.slice(5);

    // Fetch from Have I Been Pwned API
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    if (!response.ok) throw new Error('API request failed');

    const text = await response.text();
    const lines = text.split('\n');

    for (const line of lines) {
        const [hashSuffix, count] = line.split(':');
        if (hashSuffix === suffix) {
            return parseInt(count, 10);
        }
    }

    return 0;
}