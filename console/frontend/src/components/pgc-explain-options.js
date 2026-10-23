import { html, nothing } from 'lit';
import { help } from '../base.js';
import { t } from '../i18n.js';

// The explain options, shared by the Single check view and the Scenarios'
// "why" on a result: "Only the deciding path" (p_successful_only) and
// "Redact identifiers" (p_redact — forced on, and disabled, for a person
// without can_test_explain_full). onChange({successfulOnly, redact}) is
// called with the new pair; the caller keeps the state and re-explains.
export function explainOptions({ successfulOnly, redact, explainFull, onChange, policyNote = nothing }) {
  return html`<div class="actions explain-options">
    <label
      class="check"
      title=${t('Keep only the steps that contributed to the decision (p_successful_only).')}
    >
      <input
        type="checkbox"
        .checked=${successfulOnly}
        data-testid="explain-successful-only"
        @change=${(e) => onChange({ successfulOnly: e.target.checked, redact })}
      />
      ${t('Only the deciding path')}
    </label>
    <label
      class="check"
      title=${t('Strip subject and object identifiers and free text; keep types, relations, reasons and results (p_redact) — what an untrusted UI should see.')}
    >
      <input
        type="checkbox"
        .checked=${redact || !explainFull}
        ?disabled=${!explainFull}
        data-testid="explain-redact"
        @change=${(e) => onChange({ successfulOnly, redact: e.target.checked })}
      />
      ${t('Redact identifiers')}
    </label>
    ${explainFull ? nothing : policyNote}
    ${help('"Only the deciding path" hides the branches that were tried and failed; "Redact" shows the trace the way a client without audit rights would get it.')}
  </div>`;
}
