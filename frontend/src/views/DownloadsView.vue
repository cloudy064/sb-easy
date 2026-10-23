<template>
  <div>
    <div class="page-header">
      <h2>{{ t('page.downloads.title') }}</h2>
      <p class="text-sm text-muted">{{ t('page.downloads.desc') }}</p>
    </div>

    <div class="platform-grid">
      <article v-for="platform in platforms" :key="platform.id" class="card platform-card" :data-platform="platform.id">
        <div class="platform-heading">
          <h3>{{ platform.name }}</h3>
          <span class="stage-badge">{{ t(`downloads.channel.${platform.release?.channel ?? 'unpublished'}`) }}</span>
        </div>
        <p class="text-sm text-muted platform-summary">{{ t(`downloads.summary.${platform.id}`) }}</p>
        <dl class="version-details">
          <div><dt>{{ t('downloads.version') }}</dt><dd>{{ platform.release?.version ?? platform.version }}</dd></div>
          <div><dt>{{ t('downloads.core') }}</dt><dd>sing-box {{ platform.release?.core_version ?? currentCore }}</dd></div>
          <div><dt>{{ t('downloads.requirements') }}</dt><dd>{{ t(`downloads.requirements.${platform.id}`) }}</dd></div>
        </dl>
        <template v-if="platform.release">
          <div class="download-actions">
            <a v-for="artifact in platform.release.artifacts" :key="artifact.name" class="btn-primary download-button"
               :href="artifact.url" target="_blank" rel="noopener noreferrer">
              {{ artifact.architecture === 'universal' ? t('downloads.universal') : artifact.architecture }} · {{ artifact.format.toUpperCase() }}
              <small>{{ Math.ceil(artifact.size / 1048576) }} MiB</small>
            </a>
          </div>
          <p class="text-sm release-note">{{ t(`downloads.notice.${platform.id}`) }}</p>
          <p class="text-sm release-note">{{ t(`downloads.trust.${platform.release.channel}`) }}</p>
          <p v-if="platform.release.features?.packet_capture === false" class="text-sm release-note">{{ t('downloads.captureUnavailable') }}</p>
          <div class="release-links">
            <a :href="platform.release.release_url" target="_blank" rel="noopener noreferrer">{{ t('downloads.releaseNotes') }}</a>
            <a :href="platform.release.checksums_url" target="_blank" rel="noopener noreferrer">SHA-256</a>
            <a :href="platform.release.source_url" target="_blank" rel="noopener noreferrer">{{ t('downloads.matchingSource') }}</a>
          </div>
          <details class="artifact-digests">
            <summary>{{ t('downloads.checksums') }}</summary>
            <div v-for="artifact in platform.release.artifacts" :key="artifact.name">
              <span>{{ artifact.name }}</span><code>{{ artifact.sha256 }}</code>
            </div>
          </details>
        </template>
        <p v-else class="text-sm text-muted unavailable">{{ t('downloads.noPackage') }}</p>
        <div class="source-build">
          <span>{{ t('downloads.sourceVersion') }} <strong>{{ platform.version }}</strong> · sing-box {{ currentCore }}</span>
          <span v-if="platform.release?.version !== platform.version" class="text-muted">{{ t('downloads.notPublished') }}</span>
          <a :href="platform.docs" target="_blank" rel="noopener noreferrer">{{ t('downloads.buildDocs') }}</a>
        </div>
      </article>
    </div>
    <p class="card notice text-sm text-muted">{{ t('downloads.enroll') }}</p>
  </div>
</template>

<script setup lang="ts">
import releases from '../../../config/client-releases.json'
import runtime from '../../../config/runtime-versions.json'
import { useI18n } from '../composables/i18n'

const { t } = useI18n()
interface Release {
  version: string
  core_version: string
  channel: string
  release_url: string
  checksums_url: string
  source_url: string
  features?: { packet_capture?: boolean; http_debug?: boolean }
  artifacts: Array<{ name: string; architecture: string; format: string; size: number; url: string; sha256: string }>
}
const published: Partial<Record<string, Release>> = releases.published
const currentCore = runtime.sing_box.version
const names = { android: 'Android', windows: 'Windows', linux: 'Linux desktop', apple: 'macOS / iOS / tvOS' }
const platforms = (Object.keys(names) as Array<keyof typeof names>).map(id => ({
  id, name: names[id], version: releases.development[id].version, release: published[id],
  docs: `${releases.repository}/blob/master/${id}/README.md`,
}))
</script>

<style scoped>
.page-header p { margin-top: .3rem; }
.platform-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; }
.platform-card { padding: 1.5rem; min-width: 0; }
.platform-heading { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: .6rem; }
.platform-heading h3 { font-size: 1.2rem; }
.stage-badge { color: var(--accent); font-size: .72rem; border: 1px solid var(--paper-border); border-radius: 20px; padding: .3rem .65rem; }
.platform-summary { line-height: 1.65; margin: 1rem 0; min-height: 3.3em; }
.version-details { display: flex; flex-wrap: wrap; gap: 1.2rem; margin: 1rem 0 1.3rem; }
.version-details dt { color: var(--ink-muted); font-size: .72rem; margin-bottom: .3rem; }
.version-details dd { margin: 0; font-size: .85rem; font-weight: 600; }
.download-actions, .release-links { display: flex; gap: .6rem; flex-wrap: wrap; }
.download-button { display: inline-flex; align-items: center; gap: .45rem; padding: .65rem .85rem; border-radius: var(--radius-sm); text-decoration: none; font-size: .8rem; }
.download-button small { font-size: .65rem; font-weight: 400; opacity: .8; }
.release-note { margin: 1rem 0 .6rem; color: var(--ink-muted); line-height: 1.6; }
.release-links { font-size: .78rem; gap: 1rem; }
.artifact-digests { margin-top: 1rem; color: var(--ink-muted); font-size: .72rem; }
.artifact-digests summary { cursor: pointer; }
.artifact-digests div { margin-top: .75rem; }
.artifact-digests span, .artifact-digests code { display: block; overflow-wrap: anywhere; }
.artifact-digests code { margin-top: .25rem; user-select: all; }
.source-build { margin-top: 1.3rem; padding-top: 1rem; border-top: 1px solid var(--paper-border); display: flex; flex-wrap: wrap; gap: .5rem .8rem; font-size: .76rem; }
.unavailable { padding: 1rem 0; }
.notice { margin-top: 1rem; padding: 1rem 1.3rem; line-height: 1.65; }
@media (max-width: 850px) { .platform-grid { grid-template-columns: 1fr; } }
@media (max-width: 400px) { .platform-card { padding: 1.1rem; } .download-button { flex-grow: 1; justify-content: center; } }
</style>
