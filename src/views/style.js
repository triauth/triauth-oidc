/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// The stylesheet of every page, inlined into <style> by layout.js. It follows the plain pages of the
// triauth family (attest.triauth.org): Inter, the brand blue as the one accent, a readable column, no
// app chrome. Form fields and the status blocks follow the triauth-js playground. The domain and
// credentials pages are wider, with cards and label-value rows, like a settings dashboard. Edit
// freely: nothing in here is read by code.

export default `
:root {
  --page: #fcfcfc;
  --panel: #ffffff;
  --ink: #213547;
  --text: #3c3c43;
  --muted: #6b6f76;
  --line: #e5e7eb;
  --field: #d2d6dc;
  --soft: #f3f4f6;
  --brand: #1f61eb;
  --brand-dark: #174fc4;
  --brand-ring: rgba(31, 97, 235, .15);
  --brand-soft: #eef3fe;
  --error: #b91c1c;
  --error-soft: #fdf2f2;
  --ok: #1e6b30;
  --ok-soft: #ecf8ef;
  --warn: #92400e;
  --warn-soft: #fffbeb;
  --sunken: #f9fafb;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}

*, *::before, *::after {
  box-sizing: border-box;
}
body {
  margin: 0;
  min-height: 100dvh;
  display: flex;
  flex-direction: column;
  background: var(--page);
  color: var(--ink);
  font: 16px/1.7 Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
}
a {
  color: var(--brand);
}
code, pre, .mono {
  font-family: var(--mono);
}
code {
  font-size: .9em;
  overflow-wrap: anywhere;
}
.mono {
  font-size: .875rem;
  overflow-wrap: anywhere;
}

/* One line at the top: the mark and the name, so the viewer knows where they are */
header {
  border-bottom: 1px solid var(--line);
}
header a {
  display: block;
  max-width: 42rem;
  margin: 0 auto;
  padding: .875rem 1.5rem;
  font-size: .875rem;
  font-weight: 600;
  color: inherit;
  text-decoration: none;
}
header .mark {
  margin-right: .5rem;
}
header .name {
  font-weight: 500;
  color: var(--muted);
}

main {
  flex: 1;
  width: 100%;
  max-width: 42rem;
  margin: 0 auto;
  padding: 2.5rem 1.5rem 3rem;
}
.wide header a, .wide main {
  max-width: 52rem;
}
h1 {
  margin: 0 0 1rem;
  font-size: 2rem;
  line-height: 1.25;
  font-weight: 600;
  letter-spacing: -.02em;
  overflow-wrap: anywhere;
}
h2 {
  margin: 2rem 0 .5rem;
  font-size: 1.25rem;
  font-weight: 600;
  letter-spacing: -.01em;
}
p {
  margin: .75rem 0;
}

/* The home page: a larger headline with a quieter second line, the apps it works with, and
   three columns of short points (numbered for the steps) */
h1.hero {
  font-size: clamp(2rem, 6vw, 2.75rem);
  line-height: 1.15;
  letter-spacing: -.03em;
}
h1 .quiet {
  display: block;
  color: var(--muted);
}
.hero + .lead {
  max-width: 40rem;
}
.works {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: .5rem;
  margin: 1.25rem 0 0;
  font-size: .875rem;
  color: var(--muted);
}
.chips {
  display: contents;
  list-style: none;
}
.chips a {
  display: inline-block;
  padding: .125rem .75rem;
  color: var(--text);
  text-decoration: none;
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 999px;
}
.chips a:hover {
  color: var(--brand);
  border-color: var(--brand);
}
.works .more {
  color: inherit;
}
.works .more:hover {
  color: var(--brand);
}
.columns {
  display: grid;
  gap: 1.25rem;
  margin: 0;
  padding: 0;
  list-style: none;
}
@media (min-width: 40rem) {
  .columns {
    grid-template-columns: repeat(3, 1fr);
    gap: 1.5rem 2rem;
  }
}
.columns li {
  font-size: .9375rem;
  line-height: 1.6;
  color: var(--text);
}
.columns strong {
  display: block;
  margin-bottom: .125rem;
  font-size: 1rem;
  color: var(--ink);
}
.steps {
  counter-reset: step;
}
.steps li {
  counter-increment: step;
}
.steps li::before {
  content: counter(step);
  display: flex;
  align-items: center;
  justify-content: center;
  width: 1.75rem;
  height: 1.75rem;
  margin-bottom: .625rem;
  font-size: .875rem;
  font-weight: 600;
  color: var(--brand);
  background: var(--brand-soft);
  border-radius: 50%;
}
.lead {
  font-size: 1.125rem;
  color: var(--text);
}
.muted {
  font-size: .9375rem;
  color: var(--muted);
}
.mark {
  color: var(--brand);
}
pre {
  margin: .75rem 0;
  padding: 1rem 1.25rem;
  background: var(--soft);
  border-radius: 8px;
  font-size: .875rem;
  line-height: 1.6;
  overflow-x: auto;
}

/* Status: what the bridge found, or what went wrong */
.note, .ok, .err, .warn {
  margin: 1rem 0;
  padding: .75rem 1rem;
  border-radius: 8px;
  font-size: .9375rem;
}
.note {
  background: var(--soft);
  color: var(--text);
}
.ok {
  background: var(--ok-soft);
  color: var(--ok);
}
.err {
  background: var(--error-soft);
  color: var(--error);
}
.warn {
  background: var(--warn-soft);
  color: var(--warn);
}
.warn a {
  color: inherit;
  font-weight: 600;
}

/* Dashboard pages: a title with a status badge, then cards */
.page-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: .5rem 1rem;
  margin-bottom: 1rem;
}
.page-head h1 {
  margin: 0;
}
.badge {
  display: inline-flex;
  align-items: center;
  gap: .375rem;
  padding: .125rem .625rem;
  font-size: .8125rem;
  font-weight: 600;
  color: var(--muted);
  background: var(--soft);
  border-radius: 999px;
}
.badge::before {
  content: "";
  width: .5rem;
  height: .5rem;
  background: currentColor;
  border-radius: 50%;
}
.badge.ok {
  color: var(--ok);
  background: var(--ok-soft);
}
.badge.warn {
  color: var(--warn);
  background: var(--warn-soft);
}
.card {
  margin: 1.5rem 0;
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 12px;
  overflow: hidden;
}
.card-head, .card-body {
  padding: 1.25rem 1.5rem;
}
.card h2 {
  margin: 0 0 .25rem;
  font-size: 1.0625rem;
}
.card-head p, .split > div:first-child p {
  margin: 0;
  font-size: .9375rem;
  color: var(--muted);
}
.card-head + .card-body {
  padding-top: 0;
}
/* In a form card, a line sets the fields apart from the head that explains them */
form.card > .card-head + .card-body {
  padding-top: 1.25rem;
  border-top: 1px solid var(--line);
}
/* An address to check, such as the redirect URI on the sign-in page, in the text's own colour */
.card-head .note {
  margin-top: .75rem;
  font-size: .875rem;
  color: var(--text);
}

.card-body > :first-child, .split > div > :first-child {
  margin-top: 0;
}
.card-body > :last-child {
  margin-bottom: 0;
}
.card-head ol {
  margin: .625rem 0 0;
  padding-left: 1.25rem;
  font-size: .9375rem;
  color: var(--muted);
}
.card-head li + li {
  margin-top: .25rem;
}
.card-head li .hint {
  margin-top: .125rem;
}
.card-head li::marker {
  font-weight: 600;
  color: var(--ink);
}
.split {
  display: grid;
  gap: 1rem 2rem;
}
@media (min-width: 44rem) {
  .split {
    grid-template-columns: 2fr 3fr;
  }
}
.card-foot {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: .75rem 1.5rem;
  padding: .875rem 1.5rem;
  font-size: .875rem;
  color: var(--muted);
  background: var(--sunken);
  border-top: 1px solid var(--line);
}
.card-foot p {
  margin: 0;
}
.card-foot button {
  margin: 0 0 0 auto;
}
.card-foot .terms {
  flex: 1 1 20rem;
  font-size: .9375rem;
  color: var(--text);
}
/* The sign-in page: one short field in a narrow card in the middle, as on most sign-in pages, a
   button as wide as the card, and the line about the Terms under it */
.sign-in h1 {
  text-align: center;
}
.sign-in .card {
  max-width: 25rem;
  margin: 2.25rem auto;
}
.sign-in .card-foot button {
  flex: 1;
  margin: 0;
}
.sign-in .terms {
  margin: 0;
  font-size: .9375rem;
  color: var(--muted);
  text-align: center;
}
.sign-in .terms a {
  text-decoration: none;
  white-space: nowrap;
}
.rows {
  margin: 0;
  border-top: 1px solid var(--line);
}
.rows > div {
  display: grid;
  gap: .25rem 1.5rem;
  padding: .75rem 1.5rem;
  border-bottom: 1px solid var(--line);
}
.rows > div:last-child {
  border-bottom: 0;
}
@media (min-width: 44rem) {
  .rows > div {
    grid-template-columns: 9rem 1fr;
    align-items: baseline;
  }
}
.rows dt {
  font-size: .875rem;
  color: var(--muted);
}
.rows dd {
  min-width: 0;
  margin: 0;
  font-size: .9375rem;
}
.value {
  display: block;
  padding: .25rem .625rem;
  font-size: .875rem;
  color: var(--ink);
  background: var(--soft);
  border-radius: 6px;
  cursor: text;
  -webkit-user-select: all;
  user-select: all;
}
.value:hover {
  background: var(--brand-soft);
}
.value + .value {
  margin-top: .375rem;
}

/* A rarely needed section, folded into one quiet line: no card, muted text, a chevron that turns */
details.more {
  margin: 1.5rem 0;
}
details.more > summary {
  display: inline-block;
  padding: .25rem 0;
  font-size: .9375rem;
  font-weight: 500;
  color: var(--muted);
  list-style: none;
  cursor: pointer;
}
details.more > summary::-webkit-details-marker {
  display: none;
}
/* vertical-align: middle centres the chevron on the lowercase letters, not on the line box, which
   sits higher. Pointing down, the two strokes sit low in their box, so the open one is lifted. */
details.more > summary::before {
  content: "";
  display: inline-block;
  width: .4375rem;
  height: .4375rem;
  margin-right: .625rem;
  vertical-align: middle;
  border-right: 2px solid currentColor;
  border-bottom: 2px solid currentColor;
  transform: rotate(-45deg);
  transition: transform .2s;
}
details.more[open] > summary::before {
  transform: translateY(-.09rem) rotate(45deg);
}
details.more > summary:hover {
  color: var(--ink);
}
details.more > summary:focus-visible {
  outline: 2px solid var(--brand);
  outline-offset: 2px;
  border-radius: 4px;
}
details.more > .rows {
  margin-top: .75rem;
}
details.more .rows > div {
  padding-left: 0;
  padding-right: 0;
}
details.more .rows > div:last-child {
  border-bottom: 1px solid var(--line);
}
@media (prefers-reduced-motion: reduce) {
  details.more > summary::before {
    transition: none;
  }
}

/* A field added on request, as a contacts app adds a phone: a plus in a circle and a line, which give
   way to the field. The summary goes once open, so a typed value cannot be folded away; the field
   stands where the line was, and Tab moves on to it. */
details.add {
  margin-top: 1rem;
}
details.add > summary {
  display: flex;
  align-items: baseline;
  gap: .625rem;
  font-size: .9375rem;
  font-weight: 500;
  color: var(--brand);
  list-style: none;
  cursor: pointer;
}
details.add > summary::-webkit-details-marker {
  display: none;
}
details.add > summary::before {
  content: "+";
  flex: none;
  width: 1.25rem;
  height: 1.25rem;
  font-size: 1.0625rem;
  font-weight: 600;
  line-height: 1.25rem;
  text-align: center;
  background: var(--brand-soft);
  border-radius: 50%;
}
details.add > summary .hint {
  margin: .125rem 0 0;
  font-weight: 400;
}
details.add > summary:hover {
  color: var(--brand-dark);
}
details.add > summary:focus-visible {
  outline: 2px solid var(--brand);
  outline-offset: 2px;
  border-radius: 4px;
}
details.add[open] > summary {
  display: none;
}

/* The provider's settings and the credentials */
table {
  width: 100%;
  margin: .75rem 0;
  border-collapse: collapse;
  font-size: .9375rem;
}
th, td {
  padding: .5rem 1rem .5rem 0;
  text-align: left;
  vertical-align: top;
  border-bottom: 1px solid var(--line);
}
th {
  width: 8rem;
  font-weight: 600;
  color: var(--muted);
  white-space: nowrap;
}

/* Forms */
label {
  display: block;
  margin: 1.25rem 0 .375rem;
  font-size: .875rem;
  font-weight: 600;
}
/* Other names a field goes by, in parentheses after its label. The margin is the gap, so the markup
   has no space before it. */
label .aka {
  margin-left: .25rem;
  font-weight: 400;
}
input[type=text], input[type=url] {
  width: 100%;
  padding: .625rem .75rem;
  font: inherit;
  font-size: .9375rem;
  line-height: 1.4;
  color: var(--ink);
  background: var(--panel);
  border: 1px solid var(--field);
  border-radius: 8px;
}
input:focus {
  outline: none;
  border-color: var(--brand);
  box-shadow: 0 0 0 3px var(--brand-ring);
}
/* The field a problem is about, when it could be one of several */
input[aria-invalid="true"] {
  border-color: var(--error);
}
/* A field with the domain after it, in one box. When the domain leaves the field less than 8rem, it
   moves to a line of its own under the field, and a domain wider than the box wraps. The box draws
   the border and the focus ring. The line between the two parts is the domain's shadow, which the
   box cuts off wherever it meets the box's edge: so it shows on the left while the domain sits beside
   the field, and on top once it sits under it. */
.identifier {
  display: flex;
  flex-wrap: wrap;
  background: var(--panel);
  border: 1px solid var(--field);
  border-radius: 8px;
  overflow: hidden;
}
.identifier:focus-within {
  border-color: var(--brand);
  box-shadow: 0 0 0 3px var(--brand-ring);
}
.identifier input {
  flex: 1000 1 8rem;
  min-width: 0;
  border: 0;
  border-radius: 0;
  text-transform: lowercase;
}
.identifier input:focus {
  box-shadow: none;
}
.identifier .suffix {
  flex: 1 1 auto;
  padding: .625rem .75rem;
  font-size: .9375rem;
  line-height: 1.4;
  color: var(--muted);
  background: var(--soft);
  box-shadow: 0 0 0 1px var(--field);
  overflow-wrap: anywhere;
}
.check {
  display: flex;
  align-items: baseline;
  gap: .625rem;
  margin: 1rem 0;
}
.check label {
  margin: 0;
  font-size: .9375rem;
  font-weight: 400;
  color: var(--text);
}
.hint {
  display: block;
  margin: .375rem 0 0;
  font-size: .875rem;
  color: var(--muted);
}
.check .hint {
  margin: 0;
}
/* A field that belongs to a checkbox sits in the column of the box's label, so the two share one left
   edge whatever size the browser gives the box, and is hidden while the box is unchecked. Browsers
   without :has() show it always, which still works. */
.check > div {
  flex: 1;
  min-width: 0;
}
.check .reveal label {
  margin: .75rem 0 .375rem;
  font-size: .875rem;
  font-weight: 600;
  color: var(--ink);
}
.check:has(> input:not(:checked)) .reveal {
  display: none;
}
button, a.button {
  display: inline-block;
  margin: 1.5rem 0 .5rem;
  padding: .625rem 1.25rem;
  font: inherit;
  font-weight: 600;
  color: #fff;
  background: var(--brand);
  border: 1px solid transparent;
  border-radius: 8px;
  text-decoration: none;
  cursor: pointer;
}
button:hover, a.button:hover {
  background: var(--brand-dark);
}
button:focus-visible, a:focus-visible {
  outline: 2px solid var(--brand);
  outline-offset: 2px;
}

footer {
  padding: 1.25rem 1.5rem;
  font-size: .8125rem;
  color: var(--muted);
  text-align: center;
}
footer a {
  color: inherit;
  text-decoration: none;
}
`;
