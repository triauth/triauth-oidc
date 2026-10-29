/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// The home page, in the cards of the domain's page: what the bridge does, the card that opens a
// domain's page, how it works in three steps, and what it keeps. Written for the admin who sets an
// app up; users arrive at a sign-in page instead.
//
//   problem   a sentence about what was typed, when it was not a domain the bridge serves

import { html } from '../lib/html.js';

const APPS = ['Grafana', 'GitLab', 'Nextcloud', 'Proxmox', 'Cloudflare Access', 'Outline'];

export default ({ problem }) => html`
<h1 class="hero">Sign in with triauth
  <span class="quiet">to apps that support OpenID Connect.</span>
<!--  <span class="quiet">In the apps you already use.</span>-->
</h1>
<!--<p class="lead">Most apps with a “Sign in with SSO” button can sign people in with <a href="https://www.triauth.org/">triauth</a>. Nothing to install. Nothing to register. No passwords to remember.</p>-->
<div class="works"><span>Works with</span><ul class="chips">${APPS.map((app) => html`<li>${app}</li>`)}</ul><span>and more</span></div>
<form class="card" method="get" action="/">
<div class="card-body split">
<div>
<h2>One provider for your whole team</h2>
  <p>Once you setup OpenID Connect (OIDC) for an app everyone under your domain will be able to sign in there with triauth.</p>
<!--  <p>Enter the domain people sign in with. See whether it's ready, get its settings, and connect your apps.</p>-->
</div>
<div>
${problem ? html`<p class="err">${problem}</p>` : ''}
<label for="domain">Your identifier or domain</label>
<input id="domain" type="text" name="domain" placeholder="e.g., example.com" autocomplete="off" autocapitalize="none" spellcheck="false" required>

</div>
</div>
<div class="card-foot">
<button type="submit">Continue</button>
</div>
</form>
<section class="card">
<div class="card-head">
<h2>How it works</h2>
</div>
<div class="card-body">
<ol class="columns steps">
<li><strong>Enter your domain</strong> Get your own OpenID Connect provider in seconds. No sign-up, nothing to host.</li>
<li><strong>Connect the app</strong> Go to OIDC configuration in the app you want to connect, and copy-paste the settings.</li>
<li><strong>Sign in</strong> Everyone at your domain will now be able to sign in to the app with triauth.</li>
</ol>
</div>
</section>
<section class="card">
<div class="card-head">
<h2>Private by design</h2>
</div>
<div class="card-body">
<ul class="columns">
<li><strong>No accounts.</strong> People sign in with the triauth identity they already have.</li>
<li><strong>No passwords.</strong> Every sign-in is approved in the person's own authenticator.</li>
<li><strong>Built to forget.</strong> No app registry, no accounts, and no user database.</li>
</ul>
</div>
</section>
<p class="muted" style="text-align:center;"><a href="https://github.com/triauth/triauth-oidc">triauth-oidc bridge</a> is provided for free by the <a href="https://www.triauth.org/">triauth project</a>
</p>`;

