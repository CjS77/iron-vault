// SPDX-License-Identifier: MPL-2.0
// Brands the manual's menu bar to match the landing page: the IronVault lockup replaces the book title and links back to
// the landing page, which the website serves one level above the manual (site/build.sh puts the book in _site/manual/).
// The theme list keeps Auto, Light and Dark; iron-vault.css maps mdbook's other themes onto these two.

(() => {
    const brandLink = () => {
        const link = document.createElement('a');
        link.className = 'ivb-brand';
        link.href = `${path_to_root}../`;
        link.title = 'IronVault home';
        link.setAttribute('aria-label', 'IronVault home');
        link.innerHTML = `
            <img class="ivb-lockup" src="${path_to_root}assets/ironvault-lockup-dark.svg" alt="" width="157" height="26">
            <img class="ivb-mark" src="${path_to_root}assets/ironvault-mark.svg" alt="" width="30" height="26">
            <span class="ivb-section">Manual</span>`;
        // The menu title scrolls the page to the top on click; the link should navigate instead.
        link.addEventListener('click', (event) => event.stopPropagation());
        return link;
    };

    const title = document.querySelector('#mdbook-menu-bar .menu-title');
    if (title) {
        title.replaceChildren(brandLink());
    }

    const coal = document.getElementById('mdbook-theme-coal');
    if (coal) {
        coal.textContent = 'Dark';
    }
})();
