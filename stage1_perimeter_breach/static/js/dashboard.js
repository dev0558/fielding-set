document.addEventListener('DOMContentLoaded', function() {
    var form = document.querySelector('form');
    if (form) {
        form.addEventListener('submit', function() {
            var btn = form.querySelector('.btn-login');
            if (btn) {
                btn.textContent = 'Authenticating...';
                btn.disabled = true;
            }
        });
    }

    // Auto-refresh dashboard stats from API
    // TODO: re-enable after v7.4.5 upgrade
    // var endpoints = [
    //     '/api/v1/system/status',
    //     '/api/v1/fortiguard/update-check',
    //     '/api/v1/fgfm/daemon'
    // ];
    // endpoints.forEach(function(url) {
    //     fetch(url).then(r => r.json()).then(data => {
    //         console.log('[FMG Dashboard]', url, data);
    //     });
    // });
});
