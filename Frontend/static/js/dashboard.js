document.addEventListener('DOMContentLoaded', function() {
    const fileInput = document.getElementById('fileInput');
    const uploadForm = document.getElementById('uploadForm');
    const fileSizeError = document.getElementById('fileSizeError');

    uploadForm.addEventListener('submit', function(event) {
        const maxFileSize = 5 * 1024 * 1024; // 5 MB limit
        const file = fileInput.files[0];

        if (file && file.size > maxFileSize) {
            fileSizeError.style.display = 'block';
            event.preventDefault(); // Prevent form submission
        } else {
            fileSizeError.style.display = 'none';
        }
    });
});
