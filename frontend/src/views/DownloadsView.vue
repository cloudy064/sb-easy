<template>
  <div>
    <div class="page-header">
      <h2>{{ t('page.downloads.title') }}</h2>
      <p class="text-sm text-muted" style="margin-top:0.25rem">{{ t('page.downloads.desc') }}</p>
    </div>

    <div class="download-card card">
      <div class="download-copy">
        <span class="stage-badge">{{ t('downloads.stage') }}</span>
        <h3>sb-easy Android</h3>
        <p class="text-sm text-muted summary">{{ t('downloads.summary') }}</p>

        <div class="details">
          <div><span>{{ t('downloads.version') }}</span><strong>1.0.2</strong></div>
          <div><span>{{ t('downloads.core') }}</span><strong>sing-box 1.13.12</strong></div>
          <div><span>{{ t('downloads.android') }}</span><strong>{{ t('downloads.android.value') }}</strong></div>
        </div>

        <div class="download-actions">
          <a
            class="btn-primary download-button"
            href="/downloads/sb-easy-android.apk"
            download="sb-easy-android.apk"
          >
            <svg width="16" height="16" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.8">
              <path d="M9 2v9"/><path d="M5.5 8.5L9 12l3.5-3.5"/><path d="M3 15h12"/>
            </svg>
            {{ t('downloads.action.arm64') }}
          </a>
          <a
            class="btn-secondary download-button"
            href="/downloads/sb-easy-android-universal.apk"
            download="sb-easy-android-universal.apk"
          >{{ t('downloads.action.universal') }}</a>
          <a
            class="release-link"
            href="https://github.com/cloudy064/sb-easy/releases/tag/android-v1.0.2"
            target="_blank"
            rel="noopener"
          >{{ t('downloads.action.release') }} ↗</a>
        </div>
      </div>

      <div class="phone" aria-hidden="true">
        <div class="phone-speaker"></div>
        <div class="app-mark">S</div>
        <div class="phone-title">sb-easy</div>
        <div class="phone-status"><span></span> Managed proxy</div>
        <div class="phone-button">ON</div>
      </div>
    </div>

    <div class="notice card text-sm text-muted">
      <svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6">
        <path d="M3 4h12v10H3z"/><path d="M6 7h2v2H6zM10 7h2v2h-2zM6 11h6"/>
      </svg>
      <span>{{ t('downloads.enroll') }}</span>
    </div>

    <div class="notice card text-sm text-muted">
      <svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6">
        <circle cx="9" cy="9" r="7"/><path d="M9 8v5M9 5.2v.2"/>
      </svg>
      <span>{{ t('downloads.notice') }}</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from '../composables/i18n'

const { t } = useI18n()
</script>

<style scoped>
.download-card {
  min-height: 370px;
  padding: 2.25rem;
  display: grid;
  grid-template-columns: minmax(0, 1fr) 230px;
  gap: 3rem;
  align-items: center;
  overflow: hidden;
  background:
    radial-gradient(circle at 88% 12%, color-mix(in srgb, var(--accent) 18%, transparent), transparent 38%),
    var(--paper-surface);
}

.download-copy h3 { font-size: 1.8rem; margin: 0.9rem 0 0.6rem; }
.summary { line-height: 1.65; max-width: 650px; }
.stage-badge {
  display: inline-flex;
  padding: 0.35rem 0.7rem;
  border-radius: 999px;
  color: var(--accent);
  background: color-mix(in srgb, var(--accent) 12%, transparent);
  border: 1px solid color-mix(in srgb, var(--accent) 28%, transparent);
  font-size: 0.75rem;
  font-weight: 650;
}
.details {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 0.75rem;
  margin: 1.6rem 0;
}
.details div {
  padding: 0.85rem 1rem;
  border: 1px solid var(--paper-border);
  border-radius: 10px;
  background: color-mix(in srgb, var(--paper-surface) 82%, var(--paper-bg));
}
.details span, .details strong { display: block; }
.details span { color: var(--ink-muted); font-size: 0.72rem; margin-bottom: 0.3rem; }
.details strong { font-size: 0.82rem; font-weight: 650; }
.download-button { display: inline-flex; align-items: center; gap: 0.55rem; text-decoration: none; }
.download-actions { display: flex; align-items: center; flex-wrap: wrap; gap: 0.7rem; }
.release-link { color: var(--ink-muted); font-size: 0.78rem; font-weight: 650; text-decoration: none; }
.release-link:hover { color: var(--accent); }
.phone {
  width: 190px;
  height: 330px;
  justify-self: center;
  border: 7px solid var(--ink);
  border-radius: 30px;
  background: linear-gradient(155deg, color-mix(in srgb, var(--accent) 16%, var(--paper-bg)), var(--paper-bg) 55%);
  box-shadow: 0 28px 55px rgba(0, 0, 0, 0.28);
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 17px;
}
.phone-speaker { width: 44px; height: 4px; border-radius: 4px; background: var(--ink-muted); opacity: 0.5; }
.app-mark {
  width: 54px; height: 54px; margin-top: 48px; border-radius: 17px;
  display: grid; place-items: center; background: var(--accent); color: #07130f;
  font-size: 1.55rem; font-weight: 800;
}
.phone-title { margin-top: 13px; font-weight: 700; }
.phone-status { margin-top: 7px; color: var(--ink-muted); font-size: 0.67rem; }
.phone-status span { display: inline-block; width: 6px; height: 6px; margin-right: 4px; border-radius: 50%; background: var(--accent); }
.phone-button {
  width: 82px; height: 82px; margin-top: 31px; border-radius: 50%;
  display: grid; place-items: center; color: var(--accent);
  border: 1px solid color-mix(in srgb, var(--accent) 45%, transparent);
  background: color-mix(in srgb, var(--accent) 10%, transparent);
  font-size: 0.75rem; font-weight: 700;
}
.notice { margin-top: 1rem; display: flex; align-items: flex-start; gap: 0.75rem; padding: 1rem 1.2rem; }
.notice svg { flex: 0 0 auto; margin-top: 0.1rem; }

@media (max-width: 850px) {
  .download-card { grid-template-columns: 1fr; padding: 1.5rem; }
  .phone { display: none; }
}
@media (max-width: 600px) {
  .details { grid-template-columns: 1fr; }
  .download-actions { align-items: stretch; flex-direction: column; }
  .download-button { width: 100%; justify-content: center; }
  .release-link { text-align: center; padding: 0.4rem; }
}
</style>
