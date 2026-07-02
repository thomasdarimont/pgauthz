import { LitElement, html, css } from 'lit';
import { api } from '../api.js';
import './pg-json-editor.js';

// AuthZEN 1.0 API console. Pick an endpoint, edit the templated request (built
// from the shared query fields) on the left, send it through the BFF proxy to the
// authzen-opa service, and see the response on the right. Single-store: the store
// is the authzen-opa DEFAULT_STORE (shown read-only, from the discovery doc).
const ENDPOINTS = [
  { key: 'evaluation', label: 'Evaluation' },
  { key: 'evaluations', label: 'Evaluations' },
  { key: 'search/subject', label: 'Subject search', search: true },
  { key: 'search/resource', label: 'Resource search', search: true },
  { key: 'search/action', label: 'Action search', search: true },
  { key: 'config', label: 'Configuration' },
];

export class PgAuthzen extends LitElement {
  static properties = {
    subjectType: {}, subjectId: {}, action: {}, objType: {}, objId: {}, context: {},
    searchEnabled: {}, // caller may use the reverse-search endpoints (UI hint)
    endpoint: { state: true }, request: { state: true }, response: { state: true },
    status: { state: true }, busy: { state: true }, config: { state: true },
  };

  static styles = css`
    :host { display: flex; flex-direction: column; min-height: 0; gap: var(--pg-space-2, .5rem); }
    .bar { display: flex; flex-wrap: wrap; align-items: center; gap: 2px; }
    .bar button { font: inherit; padding: var(--pg-space-1, .25rem) var(--pg-space-3, .75rem);
      border: 1px solid var(--pg-border, #d0d7de); background: var(--pg-bg, #fff); color: var(--pg-fg, #1f2328);
      border-radius: var(--pg-radius-sm, 4px); cursor: pointer; }
    .bar button.active { background: var(--pg-primary, #0969da); color: #fff; border-color: var(--pg-primary, #0969da); }
    .store { margin-left: auto; font-size: var(--pg-text-sm, .8rem); color: var(--pg-muted, #6e7781);
      display: inline-flex; align-items: center; gap: 4px; }
    .split { flex: 1 1 auto; min-height: 0; display: grid; grid-template-columns: 1fr 1fr; gap: var(--pg-space-3, .75rem); }
    .side { display: flex; flex-direction: column; min-height: 0; }
    .head { display: flex; align-items: center; gap: var(--pg-space-2, .5rem); margin-bottom: var(--pg-space-1, .25rem);
      font-size: var(--pg-text-sm, .8rem); color: var(--pg-muted, #6e7781); }
    .head code { color: var(--pg-fg, #1f2328); font: var(--pg-text-code, 12px)/1.4 var(--pg-font-mono, monospace); }
    .send { margin-left: auto; font: inherit; padding: 2px 12px; cursor: pointer; color: #fff;
      background: var(--pg-primary, #0969da); border: 1px solid var(--pg-primary, #0969da); border-radius: var(--pg-radius-sm, 4px); }
    .send:disabled { opacity: .5; cursor: default; }
    .status { margin-left: auto; font-family: var(--pg-font-mono, monospace); }
    .status.ok { color: var(--pg-allow-fg, #1a7f37); } .status.err { color: var(--pg-deny-fg, #cf222e); }
    pg-json-editor { flex: 1 1 auto; min-height: 0; }
    .muted { color: var(--pg-muted, #888); }
  `;

  constructor() {
    super();
    this.endpoint = 'evaluation';
    this.request = ''; this.response = ''; this.status = ''; this.busy = false; this.config = null;
    this.searchEnabled = true;
  }

  connectedCallback() {
    super.connectedCallback();
    this._template();
    api.authzenConfig().then((r) => { if (r.status === 200) this.config = r.body; }).catch(() => {});
  }

  // Re-template when the shared query fields change (they're the source of the
  // request body). Editing the JSON by hand is a manual override that a field
  // change deliberately resets — the fields are the canonical input.
  updated(changed) {
    const fields = ['subjectType', 'subjectId', 'action', 'objType', 'objId', 'context'];
    if (fields.some((f) => changed.has(f))) this._template();
  }

  _subject() { return { type: this.subjectType || '', id: this.subjectId || '' }; }
  _actionObj() { return { name: this.action || '' }; }
  _resource() { return { type: this.objType || '', id: this.objId || '' }; }
  _ctx() { const s = (this.context || '').trim(); if (!s) return undefined; try { return JSON.parse(s); } catch { return undefined; } }

  // Build the templated request body for the current endpoint from the query fields.
  _template() {
    if (this.endpoint === 'config') { this.request = ''; this.response = ''; this.status = ''; return; }
    let body;
    switch (this.endpoint) {
      case 'evaluation': body = { subject: this._subject(), action: this._actionObj(), resource: this._resource() }; break;
      case 'evaluations': body = { subject: this._subject(), action: this._actionObj(), evaluations: [{ resource: this._resource() }] }; break;
      // Subject search returns subject IDs, so send only the subject TYPE to
      // enumerate (id is the result); the service requires subject.type.
      case 'search/subject': body = { subject: { type: this.subjectType || '' }, action: this._actionObj(), resource: this._resource() }; break;
      case 'search/resource': body = { subject: this._subject(), action: this._actionObj(), resource: { type: this.objType || '' } }; break;
      case 'search/action': body = { subject: this._subject(), resource: this._resource() }; break;
    }
    const ctx = this._ctx();
    if (ctx !== undefined) body.context = ctx;
    this.request = JSON.stringify(body, null, 2);
    this.response = ''; this.status = '';
  }

  _pick(ep) { if (ep !== this.endpoint) { this.endpoint = ep; this._template(); } }

  async _send() {
    this.busy = true; this.status = ''; this.response = '';
    try {
      let r;
      if (this.endpoint === 'config') {
        r = await api.authzenConfig();
      } else {
        let body;
        try { body = JSON.parse(this.request); }
        catch { this.status = 'request is not valid JSON'; this.busy = false; return; }
        r = await api.authzen(this.endpoint, body);
      }
      this.status = 'HTTP ' + r.status;
      this.response = JSON.stringify(r.body, null, 2);
    } catch (e) {
      this.status = String(e.message || e);
    } finally { this.busy = false; }
  }

  render() {
    const store = this.config?.access_evaluation_endpoint ? (this.config?.store ?? 'default') : (this.config ? 'default' : '…');
    const ok = /HTTP 2\d\d/.test(this.status);
    const path = this.endpoint === 'config' ? '/.well-known/authzen-configuration' : '/access/v1/' + this.endpoint;
    const method = this.endpoint === 'config' ? 'GET' : 'POST';
    return html`
      <div class="bar" data-testid="authzen-endpoints">
        ${ENDPOINTS.map((e) => {
          const locked = e.search && !this.searchEnabled;
          return html`<button class=${this.endpoint === e.key ? 'active' : ''} data-testid="authzen-ep-${e.key.replace('/', '-')}"
            ?disabled=${locked} title=${locked ? 'reverse search requires the authzen_auditor role' : e.label}
            @click=${() => this._pick(e.key)}>${e.label}${locked ? ' 🔒' : ''}</button>`;
        })}
        <span class="store" title="the AuthZEN service is single-store (its DEFAULT_STORE)">🔒 store: ${store}</span>
      </div>
      <div class="split">
        <div class="side">
          <div class="head">request <code>${method} ${path}</code>
            <button class="send" data-testid="authzen-send" ?disabled=${this.busy} @click=${() => this._send()}>Send</button></div>
          ${this.endpoint === 'config'
            ? html`<p class="muted">Discovery endpoint — <code>GET</code>, no request body. Click <b>Send</b>.</p>`
            : html`<pg-json-editor .value=${this.request} @value-changed=${(e) => (this.request = e.detail.value)}></pg-json-editor>`}
        </div>
        <div class="side">
          <div class="head">response ${this.status ? html`<span class="status ${ok ? 'ok' : 'err'}">${this.status}</span>` : ''}</div>
          <pg-json-editor data-testid="authzen-response" readonly .value=${this.response}
            placeholder="(no response yet — Send the request)"></pg-json-editor>
        </div>
      </div>`;
  }
}
customElements.define('pg-authzen', PgAuthzen);
