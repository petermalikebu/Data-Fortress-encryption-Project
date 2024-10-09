// Frontend interactions for Navbar, Login Modal, and Form Switching
const navbarMenu = document.querySelector(".navbar .links");
const hamburgerBtn = document.querySelector(".hamburger-btn");
const hideMenuBtn = navbarMenu.querySelector(".close-btn");
const showPopupBtn = document.querySelector(".login-btn");
const formPopup = document.querySelector(".form-popup");
const hidePopupBtn = formPopup.querySelector(".close-btn");
const signupLoginLink = formPopup.querySelectorAll(".bottom-link a");
const emailInputLogin = document.querySelector(".form-box.login #email");
const passwordInputLogin = document.querySelector(".form-box.login #password");
const emailInputSignup = document.querySelector(".form-box.signup #email");
const passwordInputSignup = document.querySelector(".form-box.signup #password");

// scripts.js

document.addEventListener("DOMContentLoaded", function() {
    const loginBtn = document.querySelector(".login-btn");
    const closeBtns = document.querySelectorAll(".close-btn");
    const loginFormPopup = document.querySelector(".form-popup");
    const blurBgOverlay = document.querySelector(".blur-bg-overlay");

    const showLogin = document.querySelector("#login-link");
    const showSignup = document.querySelector("#signup-link");

    const loginBox = document.querySelector(".form-box.login");
    const signupBox = document.querySelector(".form-box.signup");

    // Show login form
    loginBtn.addEventListener("click", () => {
        loginFormPopup.style.display = "block";
        blurBgOverlay.style.display = "block";
        loginBox.style.display = "block";
        signupBox.style.display = "none";
    });

    // Switch to signup form
    showSignup.addEventListener("click", (e) => {
        e.preventDefault();
        loginBox.style.display = "none";
        signupBox.style.display = "block";
    });

    // Switch to login form
    showLogin.addEventListener("click", (e) => {
        e.preventDefault();
        signupBox.style.display = "none";
        loginBox.style.display = "block";
    });

    // Close form
    closeBtns.forEach((btn) => {
        btn.addEventListener("click", () => {
            loginFormPopup.style.display = "none";
            blurBgOverlay.style.display = "none";
        });
    });
});

// Function to hide the popup message after a certain duration
function hidePopupMessage() {
    const popupMessage = document.querySelector(".popup-message");
    if (popupMessage) {
        setTimeout(() => {
            popupMessage.style.display = "none";
        }, 2000); // Adjust the duration as needed
    }
}

// Mobile menu toggle
hamburgerBtn.addEventListener("click", () => {
    navbarMenu.classList.toggle("show-menu");
});
hideMenuBtn.addEventListener("click", () => hamburgerBtn.click());

// Login popup toggle
showPopupBtn.addEventListener("click", () => {
    document.body.classList.toggle("show-popup");
});
hidePopupBtn.addEventListener("click", () => showPopupBtn.click());

// Switch between login and signup form
signupLoginLink.forEach(link => {
    link.addEventListener("click", (e) => {
        e.preventDefault();
        formPopup.classList[link.id === 'signup-link' ? 'add' : 'remove']("show-signup");
    });
});

// Placeholder handling for form fields (login and signup)
function handlePlaceholder(input, placeholder) {
    input.addEventListener("input", function () {
        this.setAttribute("placeholder", this.value.trim() !== "" ? "" : placeholder);
    });
}

handlePlaceholder(emailInputLogin, "Email");
handlePlaceholder(passwordInputLogin, "Password");
handlePlaceholder(emailInputSignup, "Email");
handlePlaceholder(passwordInputSignup, "Password");

// Call the function to hide popup message after the page loads
document.addEventListener("DOMContentLoaded", hidePopupMessage);

// File Encryption and Upload
async function generateEncryptionKey() {
    return window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true, // Extractable (allows exporting the key)
        ["encrypt", "decrypt"]
    );
}

async function encryptFile(file, key) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // Initialization vector
    const fileArrayBuffer = await file.arrayBuffer();
    
    const encryptedContent = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        fileArrayBuffer
    );

    return { iv, encryptedFile: encryptedContent };
}

async function uploadEncryptedFile(event) {
    event.preventDefault(); // Prevent form submission
    const fileInput = document.getElementById('fileInput');
    const passwordInput = document.getElementById('passwordInput');
    const file = fileInput.files[0];

    // Validate file size and type
    if (!validateFile(file)) return;

    // Encrypt the file
    const key = await generateEncryptionKey();
    const { iv, encryptedFile } = await encryptFile(file, key);

    // Prepare FormData and send to server
    const formData = new FormData();
    formData.append('file', new Blob([encryptedFile], { type: file.type }), file.name);
    formData.append('iv', new Blob([iv], { type: 'application/octet-stream' }));
    formData.append('password', passwordInput.value); // Pass the password

    try {
        const response = await fetch('/upload', { method: 'POST', body: formData });
        alert(response.ok ? 'File uploaded successfully!' : 'File upload failed.');
        if (response.ok) window.location.href = '/dashboard';
    } catch (error) {
        console.error('Error uploading file:', error);
        alert('Error uploading file.');
    }
}

// Validate file size and type
function validateFile(file) {
    const maxSize = 5 * 1024 * 1024; // 5 MB
    const allowedTypes = ['text/plain', 'application/pdf', 'image/png', 'image/jpeg', 'image/gif'];

    if (file.size > maxSize) {
        document.getElementById('fileSizeError').classList.remove('hidden');
        return false;
    } else {
        document.getElementById('fileSizeError').classList.add('hidden');
    }

    if (!allowedTypes.includes(file.type)) {
        document.getElementById('fileTypeError').classList.remove('hidden');
        return false;
    } else {
        document.getElementById('fileTypeError').classList.add('hidden');
    }

    return true;
}

// Function to handle file download and decryption
async function handleFileDownload(encryptedFileBlob, iv) {
    const response = await fetch(encryptedFileBlob);
    const encryptedArrayBuffer = await response.arrayBuffer();
    const key = await retrieveDecryptionKey(); // Implement this based on your key management
    const decryptedBlob = await decryptFile(encryptedArrayBuffer, key, iv);

    const link = document.createElement('a');
    link.href = window.URL.createObjectURL(decryptedBlob);
    link.download = 'decryptedFile.txt'; // Set your filename
    link.click();
}

// Function to decrypt file after download
async function decryptFile(encryptedFile, key, iv) {
    const decryptedContent = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        encryptedFile
    );
    return new Blob([decryptedContent]); // Return Blob for download
}

// Attach event listener to the form
document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('uploadForm');
    form.addEventListener('submit', uploadEncryptedFile);
});
