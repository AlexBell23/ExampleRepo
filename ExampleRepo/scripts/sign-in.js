


document.addEventListener('DOMContentLoaded', function() {
    // Tab switching functionality
    const tabBtns = document.querySelectorAll('.tab-btn');
    const formContainers = document.querySelectorAll('.auth-form-container');
    
    tabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const targetTab = this.getAttribute('data-tab');
            
            // Remove active class from all tabs and forms
            tabBtns.forEach(tab => tab.classList.remove('active'));
            formContainers.forEach(form => form.classList.add('hidden'));
            
            // Add active class to clicked tab and show corresponding form
            this.classList.add('active');
            document.getElementById(targetTab + '-form').classList.remove('hidden');
        });
    });
    
    // Password toggle functionality
    const passwordToggles = document.querySelectorAll('.password-toggle');
    passwordToggles.forEach(toggle => {
        toggle.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const passwordInput = document.getElementById(targetId);
            const toggleText = this.querySelector('.toggle-text');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                toggleText.textContent = 'Hide';
            } else {
                passwordInput.type = 'password';
                toggleText.textContent = 'Show';
            }
        });
    });
    
    // Password strength checker
    const registerPassword = document.getElementById('register-password');
    const strengthIndicator = document.getElementById('password-strength');
    
    if (registerPassword && strengthIndicator) {
        registerPassword.addEventListener('input', function() {
            const password = this.value;
            const strength = calculatePasswordStrength(password);
            updatePasswordStrength(strength);
        });
    }
    
    // Form submissions
    const signinForm = document.getElementById('signinForm');
    const registerForm = document.getElementById('registerForm');
    
    if (signinForm) {
        signinForm.addEventListener('submit', handleSignin);
    }
    
    if (registerForm) {
        registerForm.addEventListener('submit', handleRegister);
    }
    
    // Modal functionality
    const modal = document.getElementById('success-modal');
    const modalClose = document.getElementById('modal-close');
    
    if (modalClose) {
        modalClose.addEventListener('click', closeModal);
    }
    
    // Close modal when clicking outside
    if (modal) {
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                closeModal();
            }
        });
    }
    
    // Hamburger menu functionality
    const hamburger = document.querySelector('.hamburger');
    const navMenu = document.querySelector('.nav-menu');
    
    if (hamburger && navMenu) {
        hamburger.addEventListener('click', function() {
            hamburger.classList.toggle('active');
            navMenu.classList.toggle('active');
        });
    }
});

function calculatePasswordStrength(password) {
    let strength = 0;
    
    if (password.length >= 8) strength += 1;
    if (/[a-z]/.test(password)) strength += 1;
    if (/[A-Z]/.test(password)) strength += 1;
    if (/\d/.test(password)) strength += 1;
    if (/[^a-zA-Z\d]/.test(password)) strength += 1;
    
    return strength;
}

function updatePasswordStrength(strength) {
    const strengthFill = document.querySelector('.strength-fill');
    const strengthText = document.querySelector('.strength-text');
    
    const colors = ['#ff4757', '#ff6b7a', '#ffa502', '#2ed573', '#1e90ff'];
    const texts = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
    
    if (strengthFill && strengthText) {
        strengthFill.style.width = (strength * 20) + '%';
        strengthFill.style.backgroundColor = colors[strength - 1] || '#ddd';
        strengthText.textContent = strength > 0 ? texts[strength - 1] : 'Password strength';
    }
}

async function handleSignin(e) {
    e.preventDefault();

    const formData = new FormData(e.target);
    formData.append('action', 'signin'); // Add this line

    const submitBtn = e.target.querySelector('.auth-btn');
    const originalText = submitBtn.textContent;
    submitBtn.textContent = 'Signing In...';
    submitBtn.disabled = true;

    clearErrors();

    try {
        const response = await fetch('sign-in.php', { // Change to sign-in.php
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (result.success) {
            showModal('Welcome Back!', result.message);
            setTimeout(() => {
                window.location.href = result.redirect;
            }, 2000);
        } else {
            showError('signin-password', result.message);
        }
    } catch (error) {
        console.error('Error:', error);
        showError('signin-password', 'An error occurred. Please try again.');
    } finally {
        submitBtn.textContent = originalText;
        submitBtn.disabled = false;
    }
}

async function handleRegister(e) {
    e.preventDefault();

    const formData = new FormData(e.target);
    formData.append('action', 'register'); // Add this line

    const submitBtn = e.target.querySelector('.auth-btn');
    const originalText = submitBtn.textContent;
    submitBtn.textContent = 'Creating Account...';
    submitBtn.disabled = true;

    clearErrors();

    try {
        const response = await fetch('sign-in.php', { // Change to sign-in.php
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (result.success) {
            showModal('Registration Successful!', result.message);
            setTimeout(() => {
                window.location.href = result.redirect;
            }, 2000);
        } else {
            showError('register-email', result.message);
        }
    } catch (error) {
        console.error('Error:', error);
        showError('register-email', 'An error occurred. Please try again.');
    } finally {
        submitBtn.textContent = originalText;
        submitBtn.disabled = false;
    }
}


function displayErrors(errors, formType) {
    Object.keys(errors).forEach(field => {
        const errorId = formType === 'signin' ? 
            `signin-${field}-error` : 
            `register-${field}-error`;
        showError(errorId.replace('register-register-', 'register-'), errors[field]);
    });
}

function showError(fieldName, message) {
    // Try different error element ID patterns
    let errorElement = document.getElementById(fieldName + '-error') || 
                      document.getElementById('register-' + fieldName + '-error') ||
                      document.getElementById('signin-' + fieldName + '-error') ||
                      document.getElementById(fieldName);
    
    if (errorElement) {
        errorElement.textContent = message;
        errorElement.style.display = 'block';
        errorElement.style.color = '#ff4757';
        
        // Add error styling to the input field
        const inputField = document.getElementById(fieldName.replace('-error', '')) ||
                          document.getElementById('register-' + fieldName.replace('-error', '')) ||
                          document.getElementById('signin-' + fieldName.replace('-error', ''));
        
        if (inputField) {
            inputField.style.borderColor = '#ff4757';
            inputField.addEventListener('input', function() {
                this.style.borderColor = '';
                if (errorElement) {
                    errorElement.style.display = 'none';
                }
            }, { once: true });
        }
    }
}

function clearErrors() {
    const errorElements = document.querySelectorAll('.error-message');
    errorElements.forEach(element => {
        element.textContent = '';
        element.style.display = 'none';
    });
    
    // Clear input field error styling
    const inputFields = document.querySelectorAll('input, select');
    inputFields.forEach(field => {
        field.style.borderColor = '';
    });
}

function showModal(title, message) {
    const modal = document.getElementById('success-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalMessage = document.getElementById('modal-message');
    
    if (modal && modalTitle && modalMessage) {
        modalTitle.textContent = title;
        modalMessage.textContent = message;
        modal.style.display = 'flex';
        
        // Add animation class
        setTimeout(() => {
            modal.classList.add('show');
        }, 10);
    }
}

function closeModal() {
    const modal = document.getElementById('success-modal');
    if (modal) {
        modal.classList.remove('show');
        setTimeout(() => {
            modal.style.display = 'none';
        }, 300);
    }
}

// Social authentication handlers (placeholder functions)
function handleGoogleAuth() {
    // Implement Google OAuth integration
    console.log('Google authentication clicked');
    alert('Google authentication will be implemented with OAuth 2.0');
}

function handleFacebookAuth() {
    // Implement Facebook OAuth integration
    console.log('Facebook authentication clicked');
    alert('Facebook authentication will be implemented with Facebook SDK');
}

// Add event listeners for social buttons
document.addEventListener('DOMContentLoaded', function() {
    const googleBtns = document.querySelectorAll('.google-btn');
    const facebookBtns = document.querySelectorAll('.facebook-btn');
    
    googleBtns.forEach(btn => {
        btn.addEventListener('click', handleGoogleAuth);
    });
    
    facebookBtns.forEach(btn => {
        btn.addEventListener('click', handleFacebookAuth);
    });
});

// Form validation helpers
function validateEmail(email) {
    const emailRegex = /^[a-zA-Z0-9.%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email);
}

function validatePhone(phone) {
    const phoneRegex = /^[\+]?[1-9]?[0-9]{7,15}$/;
    return phoneRegex.test(phone.replace(/\s/g, ''));
}

function validatePassword(password) {
    // At least 8 characters, 1 uppercase, 1 lowercase, 1 number
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/;
    return passwordRegex.test(password);
}

// Real-time validation
document.addEventListener('DOMContentLoaded', function() {
    // Email validation
    const emailInputs = document.querySelectorAll('input[type="email"]');
    emailInputs.forEach(input => {
        input.addEventListener('blur', function() {
            if (this.value && !validateEmail(this.value)) {
                const errorId = this.id + '-error';
                showError(errorId, 'Please enter a valid email address');
            }
        });
    });
    
    // Phone validation
    const phoneInput = document.getElementById('register-phone');
    if (phoneInput) {
        phoneInput.addEventListener('blur', function() {
            if (this.value && !validatePhone(this.value)) {
                showError('register-phone-error', 'Please enter a valid phone number');
            }
        });
    }
    
    // Password validation
    const passwordInput = document.getElementById('register-password');
    if (passwordInput) {
        passwordInput.addEventListener('blur', function() {
            if (this.value && !validatePassword(this.value)) {
                showError('register-password-error', 'Password must be at least 8 characters with uppercase, lowercase, and number');
            }
        });
    }
});

