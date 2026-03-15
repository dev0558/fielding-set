document.addEventListener('DOMContentLoaded', function() {
    var form = document.querySelector('.login-form');
    if (form) {
        form.addEventListener('submit', function() {
            var btn = form.querySelector('.btn-login');
            if (btn) {
                btn.textContent = 'Authenticating...';
                btn.disabled = true;
            }
        });
    }
});
