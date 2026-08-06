/**
 * File JS admin del plugin: gestisce la copia degli URL metadata protetti.
 *
 * Gli URL protetti sono mostrati mascherati a schermo; il valore intero viaggia
 * nell'attributo data-copy-url del pulsante e viene copiato negli appunti.
 * L'URL e il token non vengono mai scritti in console.
 */
(function () {
    'use strict';

    var STATUS_ID = 'spid-copy-metadata-status';
    var OK_MESSAGE = 'URL copiato.';
    var KO_MESSAGE = 'Copia non riuscita. Verifica i permessi del browser.';

    function setStatus(message) {
        var status = document.getElementById(STATUS_ID);
        if (status) {
            status.textContent = message;
        }
    }

    /**
     * Fallback per contesti senza Clipboard API: textarea temporanea + execCommand.
     *
     * @param  {string} url URL da copiare.
     * @return {boolean} Esito della copia.
     */
    function copyWithFallback(url) {
        var textarea = document.createElement('textarea');
        var copied = false;

        textarea.value = url;
        textarea.setAttribute('readonly', 'readonly');
        textarea.style.position = 'fixed';
        textarea.style.top = '-1000px';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);

        try {
            textarea.select();
            copied = document.execCommand('copy') === true;
        } catch (e) {
            copied = false;
        } finally {
            document.body.removeChild(textarea);
        }

        return copied;
    }

    function handleCopyClick(event) {
        var url = event.currentTarget.dataset.copyUrl;

        if (!url) {
            setStatus(KO_MESSAGE);
            return;
        }

        if (window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(url).then(function () {
                setStatus(OK_MESSAGE);
            })['catch'](function () {
                setStatus(KO_MESSAGE);
            });
            return;
        }

        setStatus(copyWithFallback(url) ? OK_MESSAGE : KO_MESSAGE);
    }

    function init() {
        var buttons = document.querySelectorAll('.spid-copy-protected-url');
        var i;

        for (i = 0; i < buttons.length; i++) {
            buttons[i].addEventListener('click', handleCopyClick);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
