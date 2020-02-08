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
    $('.modal').on('shown.bs.modal', function() {
        $(this).find('[data-toggle="tooltip"]').tooltip();
    });

    // init endless input containers
    $('.endlessInput').endlessInput();

    // Reset forms in modals
    $('.modal').on('show.bs.modal', function() {
        $(this).find('form').resetModalForm();
    });

    // AJAX forms
    $('form.ajaxForm').each(function() {
        var form = $(this);
        form.ajaxForm({
            headers: { "CSRF-Token": getCSRF() },
            error: function() { showElement(form.data('error')); },
            success: function() { handleModalSuccess(form); },
            complete: handleCSRF
        });
    });

    // AJAX buttons
    $('.ajax-btn').each(function() {
        var btn = $(this);
        btn.on('click', function() {
            $.ajax({
                url: btn.data('action').replace('{id}', btn.data('id')),
                method: btn.data('method'),
                timeout: 2000,
                headers: { "CSRF-Token": getCSRF() },
                error: function() { showElement(btn.data('error')); },
                success: function() { handleModalSuccess(btn); },
                complete: handleCSRF
            })
        });
    });

    // init datatables
    $('.data-table').each(function() {
        var table = $(this);
        // use __ from en.js/de.js/...
        var options = { language: __, columnDefs: [] };
        var groupColumn = null;

        // data-group-column
        if (typeof table.data('groupColumn') === 'number') {
            groupColumn = table.data('groupColumn');

            // Hide the grouping column
            options.columnDefs.push({ "visible": false, "targets": groupColumn });

            // Add group headers
            options.drawCallback = function(settings) {
                var api = this.api();
                var rows = api.rows({ page: 'current' }).nodes();
                var last = null;

                api.column(groupColumn, { page: 'current' }).data().each(function(group, i) {
                    if (last !== group) {
                        if (group) {
                            $(rows).eq(i).before(
                                '<tr class="group"><td colspan="5">' + group + '</td></tr>'
                            );
                        }
                        last = group;
                    }
                });
            };
        }

        // data-gender-column
        if (typeof table.data('genderColumn') === 'number') {
            var genderColumn = table.data('genderColumn');
            options.columnDefs.push({
                "targets": genderColumn,
                "render": function(data, type, row, meta) {
                    switch (data) {
                        case 'm':
                            return '<i class="fas fa-mars"></i>';
                        case 'd':
                            return '<i class="fas fa-genderless"></i>';
                        case 'f':
                            return '<i class="fas fa-venus"></i>';
                    }
                    return '';
                }
            });
        }

        // data-age-column
        if (typeof table.data('ageColumn') === 'number') {
            var ageColumn = table.data('ageColumn');
            options.columnDefs.push({
                "targets": ageColumn,
                "render": function(data, type, row, meta) {
                    switch (data) {
                        case 'baby':
                            return '<i class="fas fa-baby"></i>';
                        case 'child':
                            return '<i class="fas fa-child"></i>';
                        case 'teen':
                            return '<i class="fas fa-male"></i>';
                        case 'youndAdult':
                            return '<i class="fas fa-user"></i>';
                        case 'adult':
                            return '<i class="fas fa-user-tie"></i>';
                        case 'senior':
                            return '<i class="fas fa-hiking"></i>';
                    }
                    return '';
                }
            });
        }

        // data-action-column
        if (typeof table.data('actionColumn') === 'number') {
            var actionColumn = table.data('actionColumn');
            var deleteModal = table.data('deleteModal');
            options.columnDefs.push({
                "targets": actionColumn,
                "render": function(data, type, row, meta) {
                    return '<div class="btn-group w-50 action-group">' +
                        `<button type="button" class="btn btn-s btn-outline-info w-25 rounded-0" data-id="${data}"><i class="fas fa-edit"></i></button>` +
                        `<button type="button" class="delbtn btn btn-s btn-outline-danger w-25 rounded-0" data-id="${data}"><i class="fas fa-trash"></i></button>` +
                        '</div>';
                }
            });
            options.createdRow = function(row, data, index) {
                $('td', row).eq(actionColumn).addClass('actionColumn');
                $('button.delbtn', row).on('click', function() {
                    $(deleteModal).modal('toggle');
                    $(deleteModal + 'Submit').data('id', $(this).data('id'));
                });
            };
        }

        var dt = table.DataTable(options);

        this.reloadTable = function() { dt.ajax.reload(); };

        if (typeof groupColumn === 'number') {
            dt.on('preDraw', function(e, settings) {
                var ordArr = dt.order();
                if (ordArr && ordArr.length > 0) {
                    if (ordArr[0][0] !== groupColumn) {
                        var ord = [
                            [groupColumn, 'asc']
                        ];
                        for (let order of ordArr) {
                            ord.push([order[0], order[1]]);
                        }
                        dt.order(ord).draw();
                        return;
                    }
                }
            });
        }
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