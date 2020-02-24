(function($) {

    $.fn.modalTooltips = function() {
        return this.each(function() {
            $(this).on('shown.bs.modal', function(e) {
                $(this).find('[data-toggle="tooltip"]').tooltip();
            });
        });
    };

    $.fn.modalResetForm = function() {
        return this.each(function() {
            $(this).on('show.bs.modal', function() {
                var form = $(this).find('form');
                form.resetEndlessForm()
                form.resetFormState();
                form.resetFormFields();
            });
        });
    };

    $.fn.modalPopulateForm = function() {
        return this.each(function() {
            $(this).on('show.bs.modal', function(e) {
                var form = $(this).find('.ajaxForm[data-fill-method]');
                if (form.length < 1) {
                    return;
                }
                if (e.relatedTarget) {
                    form.data('id', $(e.relatedTarget).data('id'));
                }
                form[0].populateForm();
            });
        });
    };

})(jQuery);