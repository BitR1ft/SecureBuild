(function () {
    'use strict';

    document.addEventListener('click', function (e) {
        var row = e.target.closest('.clickable');
        if (!row) return;
        if (e.target.closest('a, button, input, select, textarea')) return;
        var href = row.getAttribute('data-href');
        if (!href) return;
        var target = row.getAttribute('data-target');
        if (target === '_blank') {
            window.open(href, '_blank', 'noopener,noreferrer');
        } else {
            window.location.href = href;
        }
    });
})();
