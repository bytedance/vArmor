/**
 * Component interaction scripts
 *
 * @module components
 * @requires jquery
 * @requires lodash
 * Purpose:
 * 1. Handle component interactions
 * 2. Implement copy functionality
 * 3. Handle theme switching
 * 4. Implement image zoom
 */

$(document).ready(function() {
    // Theme switching
    function handleThemeSwitch() {
        const isDark = document.documentElement.classList.contains('dark');
        $('.architecture-diagram').each(function() {
            const theme = $(this).data('theme');
            if ((isDark && theme === 'dark') || (!isDark && theme === 'light')) {
                $(this).removeClass('hidden').addClass('block');
            } else {
                $(this).removeClass('block').addClass('hidden');
            }
        });
    }

    // Initialize theme handling
    handleThemeSwitch();

    // Handle smooth scroll for sections
    $('a[href^="#"]').on('click', function(e) {
        e.preventDefault();
        const target = $(this.hash);
        if (target.length) {
            $('html, body').animate({
                scrollTop: target.offset().top - 64
            }, 800, 'easeInOutCubic');
        }
    });

    // Watch for theme changes
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.attributeName === 'class') {
                handleThemeSwitch();
            }
        });
    });

    observer.observe(document.documentElement, {
        attributes: true,
        attributeFilter: ['class']
    });

    // Handle window resize for responsive behavior
    $(window).resize(_.debounce(function() {
        const modal = $('#zoom-modal');
        if (modal.is(':visible')) {
            const img = $('#zoomed-image');
            const windowHeight = $(window).height() - 100;
            const windowWidth = $(window).width() - 100;
            const imgRatio = img[0].naturalWidth / img[0].naturalHeight;
            const windowRatio = windowWidth / windowHeight;

            if (imgRatio > windowRatio) {
                img.css({
                    'width': '100%',
                    'height': 'auto'
                });
            } else {
                img.css({
                    'width': 'auto',
                    'height': '100%'
                });
            }
        }
    }, 150));
});
