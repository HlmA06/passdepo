/* static/script.js */

document.addEventListener('DOMContentLoaded', function () {
    let body = document.querySelector('body');
    body.style.opacity = 0;

    window.onload = function () {
        body.style.transition = 'opacity 0.5s';
        body.style.opacity = 1;
    };
});
