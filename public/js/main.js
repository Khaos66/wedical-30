;
// load eruda
(function() {
    var src = '/js/eruda.js';
    if (!/eruda=true/.test(window.location) &&
        localStorage.getItem('active-eruda') != 'true') return;
    document.write('<scr' +
        'ipt src="' + src + '"></scr' +
        'ipt>');
    document.write('<scr' +
        'ipt>eruda.init();</scr' +
        'ipt>');
})();

// init
(function($) {
    // tooltips
    $('[data-toggle="tooltip"]').not('.lazy-tooltip').tooltip();
    // tooltips in modals
    $('.modal').modalTooltips();
    // Reset forms in modals
    $('.modal.clear-form').modalResetForm();

    // init endless input containers
    $('.endlessInput').endlessInput();

    // AJAX forms (submit)
    $('form.ajaxForm').ajaxFormSubmit();
    // AJAX forms (populate/fill)
    $('form.ajaxForm[data-fill-method]').ajaxFillForm();
    // AJAX buttons
    $('.ajax-btn').ajaxRequest();

    // init DataTables
    $('.data-table').setupDataTable();

    // Multi-Selects with QuickSearch
    $('.quickMultiSelect').quickMultiSelect();

    // Radio toggles
    $('input[data-toggle="radio"][data-target]').each(function() {
        var input = $(this);
        var selector = input.data('target');
        input.change(function() {
            $(selector).collapse('toggle');
        });
    });
})(jQuery);

function getCSRF() {
    return document.querySelector('meta[name="csrf-token"]').getAttribute('content');
}

function setCSRF(token) {
    document.querySelector('meta[name="csrf-token"]').setAttribute('content', token);
}

function handleCSRF(jqXHR) {
    var csrf = jqXHR.getResponseHeader('CSRF-Token');
    if (csrf) { setCSRF(csrf); }
}

function showElement(selector) {
    if (selector) { $(selector).show(); }
}

function handleModalSuccess(element) {
    if (element.data('modal')) {
        $(element.data('modal')).modal('hide');
    }
    if (element.data('redrawTable')) {
        $(element.data('redrawTable')).each(function() {
            this.reloadTable();
        });
    }
}