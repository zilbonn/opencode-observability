<template>
  <div class="bg-[var(--theme-bg-tertiary)] border-b border-[var(--theme-border-primary)] p-4">
    <div class="flex items-center justify-between mb-4">
      <h2 class="text-lg font-semibold text-[var(--theme-text-primary)]">Security Metrics</h2>
      <button
        @click="fetchMetrics"
        class="px-3 py-1 text-sm bg-[var(--theme-primary)] text-white rounded hover:bg-[var(--theme-primary-hover)] transition-colors"
        :disabled="loading"
      >
        {{ loading ? 'Loading...' : 'Refresh' }}
      </button>
    </div>

    <div v-if="error" class="mb-4 p-2 bg-red-100 text-red-700 rounded text-sm">
      {{ error }}
    </div>

    <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
      <!-- Token Usage -->
      <div class="bg-[var(--theme-bg-secondary)] rounded-lg p-3">
        <div class="text-xs text-[var(--theme-text-tertiary)] mb-1">Total Tokens</div>
        <div class="text-xl font-bold text-[var(--theme-text-primary)]">
          {{ formatNumber(dashboard?.tokens?.total_tokens || 0) }}
        </div>
      </div>

      <!-- Cost -->
      <div class="bg-[var(--theme-bg-secondary)] rounded-lg p-3">
        <div class="text-xs text-[var(--theme-text-tertiary)] mb-1">Est. Cost</div>
        <div class="text-xl font-bold text-green-500">
          ${{ (dashboard?.tokens?.total_cost || 0).toFixed(4) }}
        </div>
      </div>

      <!-- Findings -->
      <div class="bg-[var(--theme-bg-secondary)] rounded-lg p-3">
        <div class="text-xs text-[var(--theme-text-tertiary)] mb-1">Findings</div>
        <div class="text-xl font-bold text-[var(--theme-text-primary)]">
          {{ dashboard?.findings?.total_findings || 0 }}
        </div>
      </div>

      <!-- Critical/High -->
      <div class="bg-[var(--theme-bg-secondary)] rounded-lg p-3">
        <div class="text-xs text-[var(--theme-text-tertiary)] mb-1">Critical/High</div>
        <div class="flex gap-2">
          <span class="px-2 py-0.5 bg-red-500 text-white text-sm rounded">
            {{ dashboard?.findings?.by_severity?.critical || 0 }}
          </span>
          <span class="px-2 py-0.5 bg-orange-500 text-white text-sm rounded">
            {{ dashboard?.findings?.by_severity?.high || 0 }}
          </span>
        </div>
      </div>

      <!-- Tool Calls -->
      <div class="bg-[var(--theme-bg-secondary)] rounded-lg p-3">
        <div class="text-xs text-[var(--theme-text-tertiary)] mb-1">Tool Calls</div>
        <div class="text-xl font-bold text-[var(--theme-text-primary)]">
          {{ totalToolCalls }}
        </div>
      </div>

      <!-- WSTG Coverage -->
      <div class="bg-[var(--theme-bg-secondary)] rounded-lg p-3">
        <div class="text-xs text-[var(--theme-text-tertiary)] mb-1">WSTG Coverage</div>
        <div class="text-xl font-bold text-[var(--theme-text-primary)]">
          {{ (dashboard?.wstg?.coverage_percentage || 0).toFixed(0) }}%
        </div>
      </div>
    </div>

    <!-- Severity Breakdown -->
    <div v-if="dashboard?.findings?.total_findings > 0" class="mt-4">
      <div class="text-sm text-[var(--theme-text-secondary)] mb-2">Findings by Severity</div>
      <div class="flex gap-2 flex-wrap">
        <span v-if="dashboard?.findings?.by_severity?.critical" class="px-3 py-1 bg-red-600 text-white text-sm rounded-full">
          {{ dashboard.findings.by_severity.critical }} Critical
        </span>
        <span v-if="dashboard?.findings?.by_severity?.high" class="px-3 py-1 bg-orange-500 text-white text-sm rounded-full">
          {{ dashboard.findings.by_severity.high }} High
        </span>
        <span v-if="dashboard?.findings?.by_severity?.medium" class="px-3 py-1 bg-yellow-500 text-black text-sm rounded-full">
          {{ dashboard.findings.by_severity.medium }} Medium
        </span>
        <span v-if="dashboard?.findings?.by_severity?.low" class="px-3 py-1 bg-blue-500 text-white text-sm rounded-full">
          {{ dashboard.findings.by_severity.low }} Low
        </span>
        <span v-if="dashboard?.findings?.by_severity?.info" class="px-3 py-1 bg-gray-500 text-white text-sm rounded-full">
          {{ dashboard.findings.by_severity.info }} Info
        </span>
      </div>
    </div>

    <!-- Tool Effectiveness (top 5) -->
    <div v-if="dashboard?.tools?.length > 0" class="mt-4">
      <div class="text-sm text-[var(--theme-text-secondary)] mb-2">Top Tools by Usage</div>
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
        <div
          v-for="tool in topTools"
          :key="tool.tool_name"
          class="bg-[var(--theme-bg-secondary)] rounded p-2 flex justify-between items-center"
        >
          <span class="text-sm text-[var(--theme-text-primary)] truncate">{{ tool.tool_name }}</span>
          <div class="flex items-center gap-2">
            <span class="text-xs text-[var(--theme-text-tertiary)]">{{ tool.total_calls }} calls</span>
            <span
              :class="[
                'text-xs px-1.5 py-0.5 rounded',
                tool.success_rate >= 90 ? 'bg-green-500 text-white' :
                tool.success_rate >= 70 ? 'bg-yellow-500 text-black' :
                'bg-red-500 text-white'
              ]"
            >
              {{ tool.success_rate.toFixed(0) }}%
            </span>
            <span v-if="tool.vulnerabilities_found > 0" class="text-xs bg-purple-500 text-white px-1.5 py-0.5 rounded">
              {{ tool.vulnerabilities_found }} vulns
            </span>
          </div>
        </div>
      </div>
    </div>

    <!-- Sessions Summary -->
    <div v-if="dashboard?.sessions?.total > 0" class="mt-4">
      <div class="text-sm text-[var(--theme-text-secondary)] mb-2">Sessions</div>
      <div class="flex gap-2">
        <span class="px-3 py-1 bg-green-500 text-white text-sm rounded-full">
          {{ dashboard.sessions.running }} Running
        </span>
        <span class="px-3 py-1 bg-blue-500 text-white text-sm rounded-full">
          {{ dashboard.sessions.completed }} Completed
        </span>
        <span v-if="dashboard.sessions.failed > 0" class="px-3 py-1 bg-red-500 text-white text-sm rounded-full">
          {{ dashboard.sessions.failed }} Failed
        </span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import type { MetricsDashboard } from '../types';
import { API_BASE_URL } from '../config';

const dashboard = ref<MetricsDashboard | null>(null);
const loading = ref(false);
const error = ref<string | null>(null);
let refreshInterval: number | null = null;

const totalToolCalls = computed(() => {
  if (!dashboard.value?.tools) return 0;
  return dashboard.value.tools.reduce((sum, tool) => sum + tool.total_calls, 0);
});

const topTools = computed(() => {
  if (!dashboard.value?.tools) return [];
  return [...dashboard.value.tools]
    .sort((a, b) => b.total_calls - a.total_calls)
    .slice(0, 6);
});

function formatNumber(num: number): string {
  if (num >= 1000000) {
    return (num / 1000000).toFixed(1) + 'M';
  }
  if (num >= 1000) {
    return (num / 1000).toFixed(1) + 'K';
  }
  return num.toString();
}

async function fetchMetrics() {
  loading.value = true;
  error.value = null;

  try {
    const response = await fetch(`${API_BASE_URL}/api/metrics/dashboard`);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    dashboard.value = await response.json();
  } catch (err) {
    error.value = `Failed to fetch metrics: ${err}`;
    console.error('Error fetching metrics:', err);
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  fetchMetrics();
  // Refresh every 30 seconds
  refreshInterval = window.setInterval(fetchMetrics, 30000);
});

onUnmounted(() => {
  if (refreshInterval) {
    clearInterval(refreshInterval);
  }
});
</script>
