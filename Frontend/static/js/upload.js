document.addEventListener('DOMContentLoaded', () => {
    const uploadForm = document.getElementById('uploadForm');
    const fileInput = document.getElementById('fileInput');
    const fileSizeError = document.getElementById('fileSizeError');
    const fileTypeError = document.getElementById('fileTypeError');

    const allowedExtensions = ['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'];
    const maxSizeInBytes = 5 * 1024 * 1024; // 5 MB

    uploadForm.addEventListener('submit', (e) => {
        const file = fileInput.files[0];

        // Clear previous errors
        fileSizeError.classList.add('hidden');
        fileTypeError.classList.add('hidden');

        if (file) {
            const fileExtension = file.name.split('.').pop().toLowerCase();

            if (!allowedExtensions.includes(fileExtension)) {
                e.preventDefault();
                fileTypeError.classList.remove('hidden');
            }

            if (file.size > maxSizeInBytes) {
                e.preventDefault();
                fileSizeError.classList.remove('hidden');
            }
        }
    });
});
