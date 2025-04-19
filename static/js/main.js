// Initialize Feather icons
document.addEventListener('DOMContentLoaded', function() {
    feather.replace();
    
    // Get elements
    const urlInput = document.getElementById('urlInput');
    const obfuscateBtn = document.getElementById('obfuscateBtn');
    const resultArea = document.getElementById('resultArea');
    const errorArea = document.getElementById('errorArea');
    const errorMessage = document.getElementById('errorMessage');
    const originalUrl = document.getElementById('originalUrl');
    const obfuscatedUrl = document.getElementById('obfuscatedUrl');
    const proxyUrl = document.getElementById('proxyUrl');
    const testLink = document.getElementById('testLink');
    const copyButtons = document.querySelectorAll('.copy-btn');
    
    // Event listeners
    if (obfuscateBtn) {
        obfuscateBtn.addEventListener('click', obfuscateUrl);
    }
    
    if (urlInput) {
        urlInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                obfuscateUrl();
            }
        });
    }
    
    // Copy button functionality
    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const targetElement = document.getElementById(targetId);
            
            if (targetElement) {
                copyToClipboard(targetElement.value);
                
                // Visual feedback
                const icon = this.querySelector('.copy-icon');
                const originalIcon = '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-copy copy-icon"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';
                const checkIcon = '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-check copy-icon"><polyline points="20 6 9 17 4 12"></polyline></svg>';
                
                icon.outerHTML = checkIcon;
                
                setTimeout(() => {
                    this.querySelector('.copy-icon').outerHTML = originalIcon;
                }, 2000);
            }
        });
    });
    
    // Function to copy text to clipboard
    function copyToClipboard(text) {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
    }
    
    // Function to obfuscate URL
    async function obfuscateUrl() {
        const url = urlInput.value.trim();
        
        // Basic validation
        if (!url) {
            showError('Please enter a URL');
            return;
        }
        
        // Validate URL format
        if (!isValidUrl(url)) {
            showError('Please enter a valid URL with http:// or https:// protocol');
            return;
        }
        
        try {
            // Show loading state
            obfuscateBtn.disabled = true;
            obfuscateBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';
            
            // Make API request
            const response = await fetch('/api/obfuscate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url })
            });
            
            const data = await response.json();
            
            // Reset button state
            obfuscateBtn.disabled = false;
            obfuscateBtn.textContent = 'Obfuscate';
            
            if (response.ok) {
                // Show result
                originalUrl.value = data.original_url;
                obfuscatedUrl.value = data.obfuscated_url;
                proxyUrl.value = data.proxy_url;
                testLink.href = data.proxy_url;
                
                // Show result area, hide error area
                resultArea.classList.remove('d-none');
                errorArea.classList.add('d-none');
            } else {
                // Show error
                showError(data.error || 'Failed to obfuscate URL');
            }
        } catch (error) {
            console.error('Error:', error);
            
            // Reset button state
            obfuscateBtn.disabled = false;
            obfuscateBtn.textContent = 'Obfuscate';
            
            showError('An error occurred while processing your request');
        }
    }
    
    // Function to show error message
    function showError(message) {
        errorMessage.textContent = message;
        errorArea.classList.remove('d-none');
        resultArea.classList.add('d-none');
    }
    
    // Function to validate URL
    function isValidUrl(url) {
        try {
            const parsedUrl = new URL(url);
            return ['http:', 'https:'].includes(parsedUrl.protocol);
        } catch (e) {
            return false;
        }
    }
});
