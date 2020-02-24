(function($) {
    $.fn.endlessInput = function() {
        return this.each(function() {
            var container = $(this);
            var templateSelector = container.data('inputTemplate');
            var defaultCounter = parseInt(container.data('startIndex') || '1');
            var counter = defaultCounter;

            // remove template from DOM, so it isn't submitted with form
            var template = $(templateSelector).clone(true);
            $(templateSelector).remove();

            // function to add a new input group
            var addFields = function() {
                var group = template.clone(true);
                var index = counter++;

                var replaceIndex = function(element, attribute) {
                    if (element.attr(attribute)) {
                        element.attr(attribute, element.attr(attribute).replace('%s', index));
                    }
                }

                group.find('input').each(function() {
                    var input = $(this);
                    replaceIndex(input, 'name');
                    replaceIndex(input, 'placeholder');
                    input.keypress(function() {
                        if (index === counter - 1) {
                            addFields();
                        }
                        input.off('keypress');
                    });
                });
                group.removeClass('collapse');
                group.addClass('endlessInputGroup');
                container.append(group);
            };

            // add first input group
            addFields();
            this.addFields = addFields;

            // Add function to reset the input group
            container.addClass('endlessInputEnabled');
            this.resetEndlessInputs = function() {
                container.find('.endlessInputGroup').remove();
                counter = defaultCounter;
                addFields();
            }
        });
    };

    $.fn.resetEndlessForm = function() {
        var endlessContainer = this.find('.endlessInput');
        if (endlessContainer.length == 0) {
            endlessContainer = this;
        }
        return endlessContainer.filter('.endlessInputEnabled').each(function() {
            this.resetEndlessInputs();
        });
    };
})(jQuery);