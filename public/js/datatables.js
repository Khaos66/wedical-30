(function($) {
    /**
     * @summary
     * Sets up DataTables with:
     * - grouping (+fixed ordering)
     * - gender/age columns
     * - action columns
     */
    $.fn.setupDataTable = function() {
        return $(this).each(function() {
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

            // data-expected-column
            if (typeof table.data('expectedColumn') === 'number') {
                var expectedColumn = table.data('expectedColumn');
                options.columnDefs.push({
                    "targets": expectedColumn,
                    "render": function(data, type, row, meta) {
                        switch (data) {
                            case 'expected':
                                return '<i class="fas fa-thumbs-up"></i>';
                            case 'unsure':
                                return '<i class="fas fa-circle-notch"></i>';
                            case 'unexpected':
                                return '<i class="fas fa-thumbs-down"></i>';
                        }
                        return '';
                    }
                });
            }

            // data-invitee-column
            if (typeof table.data('inviteeColumn') === 'number') {
                var inviteeColumn = table.data('inviteeColumn');
                options.columnDefs.push({
                    "targets": inviteeColumn,
                    "render": function(data, type, row, meta) {
                        if (row['type'] == 'guestlist') {
                            return `${row['guests'].length} <i class="fas fa-user-friends"></i>`;
                        } else {
                            return `${row['tickets']} <i class="fas fa-ticket-alt"></i>`;
                        }
                    }
                });
            }

            // data-action-column
            if (typeof table.data('actionColumn') === 'number') {
                var actionColumn = table.data('actionColumn');
                var editModal = table.data('editModal');
                var editForm = table.data('editForm');
                var deleteModal = table.data('deleteModal');
                var disableEdit = table.data('disableEdit');
                var editBtn = table.data('editBtn');
                options.columnDefs.push({
                    "targets": actionColumn,
                    "render": function(data, type, row, meta) {
                        return '<div class="btn-group w-100 action-group">' +
                            `<button type="button" class="edtbtn btn btn-s btn-outline-info w-50 rounded-0" data-id="${data}" ${disableEdit && row[disableEdit] ? 'data-disabled="yes"' : ''}><i class="fas fa-edit"></i></button>` +
                            `<button type="button" class="delbtn btn btn-s btn-outline-danger w-50 rounded-0" data-id="${data}" ${disableEdit && row[disableEdit] ? 'disabled' : ''}><i class="fas fa-trash"></i></button>` +
                            '</div>';
                    }
                });
                options.createdRow = function(row, data, index) {
                    $('td', row).eq(actionColumn).addClass('actionColumn');
                    $('button.edtbtn', row).on('click', function() {
                        let btn = $(this);
                        if (disableEdit && editBtn) {
                            $(editBtn).attr('disabled', btn.data('disabled') === 'yes');
                        }

                        $(editModal).modal('toggle');
                        var form = $(editForm);
                        form.data('id', btn.data('id'));
                        if (form[0].populateForm) {
                            form[0].populateForm();
                        }
                    });
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
    };

})(jQuery);