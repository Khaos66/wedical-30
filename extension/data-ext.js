module.exports = (function() {
    var dataExt = {};

    /**
     * Counts array entries based on a selector
     * @param {Array} collection List of objects
     * @param {Function} selector Selector function to select the counted value
     * @param {Array} keys List of possible keys (optional)
     * @param {Function} valueSelector Function that returns the increment value
     */
    function countBy(collection, selector, keys, valueSelector) {
        if (!selector) {
            selector = (x) => x;
        }
        if (!valueSelector) {
            valueSelector = (x) => 1;
        }
        let sums = {};
        if (keys) {
            for (var key of keys) {
                sums[key] = 0;
            }
        }

        for (let entry of collection) {
            let value = selector(entry);
            if (keys) {
                if (keys.indexOf(value) < 0) {
                    continue;
                }
            }

            let increment = valueSelector(entry);
            if (sums[value]) {
                sums[value] += increment;
            } else {
                sums[value] = increment;
            }
        }
        return sums;
    };
    dataExt.countBy = countBy;

    /**
     * Summs arrays or objects with nummeric values
     * @param {any} collection Array or object
     */
    function sum(collection) {
        if (Array.isArray(collection)) {
            return collection.reduce((a, b) => a + b, 0)
        }
        let sum = 0;
        for (var [key, val] of Object.entries(collection)) {
            let value = parseInt(val);
            sum += value;
        }
        return sum;
    }
    dataExt.sum = sum;

    return dataExt;
})();