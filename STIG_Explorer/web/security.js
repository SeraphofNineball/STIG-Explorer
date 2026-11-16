/* Small, side-effect-free output encoding helpers. Tested under Node and used
 * by the offline browser UI without any external dependencies. */
(function (root) {
  "use strict";
  function csvCell(value) {
    let cell = String(value ?? "");
    // Spreadsheet apps may treat quoted CSV cells as formulas. A leading
    // apostrophe forces text interpretation (including whitespace-prefixed).
    if (/^[\s\u0000-\u001f\u007f-\u009f]*[=+\-@]/u.test(cell)) cell = "'" + cell;
    return '"' + cell.replace(/"/g, '""') + '"';
  }
  const api = { csvCell };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.STIGX_SECURITY = api;
})(typeof window !== "undefined" ? window : globalThis);
