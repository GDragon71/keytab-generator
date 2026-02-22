document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('keytabForm');
    const submitBtn = document.getElementById('submitBtn');
    const messageDiv = document.getElementById('message');
    const btnText = submitBtn.querySelector('.btn-text');
    const spinner = submitBtn.querySelector('.spinner');

    form.addEventListener('submit', async function(e) {
        e.preventDefault();

        // Get form values
        const domain = document.getElementById('domain').value.trim();
        const spn = document.getElementById('spn').value.trim();
        const password = document.getElementById('password').value;

        // Validate
        if (!domain || !spn || !password) {
            showMessage('Please fill in all fields', 'error');
            return;
        }

        // Show loading state
        submitBtn.disabled = true;
        btnText.style.display = 'none';
        spinner.style.display = 'block';
        messageDiv.style.display = 'none';

        try {
            // Prepare request
            const response = await fetch('/api/generate-keytab', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    domain: domain,
                    spn: spn,
                    password: password
                })
            });

            if (response.ok) {
                // Get filename from content-disposition header
                const contentDisposition = response.headers.get('Content-Disposition');
                let filename = 'keytab.keytab';
                
                if (contentDisposition) {
                    const matches = contentDisposition.match(/filename[^;=\n]*=(?:(['"]).*?\1|[^;\n]*)/);
                    if (matches && matches.length > 1) {
                        filename = matches[1].replace(/['"]/g, '');
                    }
                }

                // Download file
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = filename;
                document.body.appendChild(link);
                link.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(link);

                showMessage('✓ Keytab file generated and downloaded successfully!', 'success');
                
                // Clear form
                form.reset();
            } else {
                const error = await response.json();
                showMessage('Error: ' + (error.error || 'Failed to generate keytab'), 'error');
            }
        } catch (error) {
            console.error('Error:', error);
            showMessage('Error: ' + error.message, 'error');
        } finally {
            submitBtn.disabled = false;
            btnText.style.display = 'inline';
            spinner.style.display = 'none';
        }
    });

    function showMessage(text, type) {
        messageDiv.textContent = text;
        messageDiv.className = `message ${type}`;
        messageDiv.style.display = 'block';

        if (type === 'success') {
            // Auto-hide success message after 5 seconds
            setTimeout(() => {
                messageDiv.style.display = 'none';
            }, 5000);
        }
    }

    // Clear message when user starts typing
    const inputs = form.querySelectorAll('input');
    inputs.forEach(input => {
        input.addEventListener('input', function() {
            if (messageDiv.classList.contains('error')) {
                messageDiv.style.display = 'none';
            }
        });
    });
});
