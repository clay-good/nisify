/**
 * Nisify Dashboard JavaScript
 *
 * Vanilla JavaScript only - no jQuery, React, or other frameworks.
 * Uses Fetch API for data loading and Canvas API for charts.
 */

// Global state
let currentData = {
    summary: null,
    maturity: null,
    gaps: null,
    evidence: null,
    trends: null
};

let sortState = {
    column: null,
    ascending: true
};

let paginationState = {
    page: 1,
    limit: 50,
    total: 0
};

// Auto-refresh state
let autoRefreshInterval = null;
let autoRefreshSeconds = 60;
let autoRefreshEnabled = false;
let lastRefreshTime = null;

// Function display names
const FUNCTION_NAMES = {
    'GV': 'Govern',
    'ID': 'Identify',
    'PR': 'Protect',
    'DE': 'Detect',
    'RS': 'Respond',
    'RC': 'Recover'
};

/**
 * Fetch JSON data from API endpoint.
 */
async function fetchJson(url) {
    try {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Fetch error:', error);
        return null;
    }
}

/**
 * Format a number with specified decimal places.
 */
function formatNumber(num, decimals = 2) {
    if (num === null || num === undefined) return '--';
    return Number(num).toFixed(decimals);
}

/**
 * Format a date string for display.
 */
function formatDate(dateStr) {
    if (!dateStr) return '--';
    const date = new Date(dateStr);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

/**
 * Escape HTML to prevent XSS.
 */
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================================================
// Index Page
// ============================================================================

async function loadIndexData() {
    const summary = await fetchJson('/api/summary');
    if (!summary) {
        showNoData();
        return;
    }

    currentData.summary = summary;

    // Update summary cards
    if (summary.maturity) {
        document.getElementById('overall-score').textContent = formatNumber(summary.maturity.overall_score);
        document.getElementById('overall-level').textContent = summary.maturity.overall_level;
        document.getElementById('evidence-count').textContent = summary.maturity.evidence_count || 0;
    }

    if (summary.gaps) {
        document.getElementById('gap-count').textContent = summary.gaps.total || 0;
        document.getElementById('critical-gaps').textContent = summary.gaps.critical_count || 0;
    }

    if (summary.trends) {
        const direction = summary.trends.direction || 'stable';
        document.getElementById('trend-direction').textContent = direction.charAt(0).toUpperCase() + direction.slice(1);
    }

    // Load function bars
    if (summary.maturity && summary.maturity.functions) {
        renderFunctionBars(summary.maturity.functions);
    }
}

function renderFunctionBars(functions) {
    const container = document.getElementById('function-bars');
    if (!container) return;

    container.innerHTML = '';

    const functionOrder = ['GV', 'ID', 'PR', 'DE', 'RS', 'RC'];

    for (const funcId of functionOrder) {
        const func = functions[funcId];
        if (!func) continue;

        const item = document.createElement('div');
        item.className = 'function-bar-item';

        const percentage = (func.score / 4.0) * 100;

        item.innerHTML = `
            <span class="function-label">${funcId} - ${FUNCTION_NAMES[funcId] || funcId}</span>
            <div class="bar-container">
                <div class="bar-fill" style="width: ${percentage}%"></div>
            </div>
            <span class="function-score">${formatNumber(func.score)}</span>
        `;

        container.appendChild(item);
    }
}

function showNoData() {
    const cards = document.getElementById('summary-cards');
    if (cards) {
        cards.innerHTML = '<div class="card"><p>No data available. Run evidence collection first.</p></div>';
    }
}

// ============================================================================
// Dashboard Page
// ============================================================================

async function loadDashboardData() {
    const [maturity, functions] = await Promise.all([
        fetchJson('/api/maturity'),
        fetchJson('/api/functions')
    ]);

    if (!maturity || maturity.error) {
        document.getElementById('overall-score').textContent = 'N/A';
        return;
    }

    currentData.maturity = maturity;

    // Update overall display
    const overall = maturity.overall;
    document.getElementById('overall-score').textContent = formatNumber(overall.score);
    document.getElementById('overall-level').textContent = overall.level;
    document.getElementById('evidence-count').textContent = overall.evidence_count || 0;

    // Update overall bar
    const barPercentage = (overall.score / 4.0) * 100;
    document.getElementById('overall-bar').style.width = barPercentage + '%';

    // Render functions grid
    if (functions && functions.functions) {
        renderFunctionsGrid(functions.functions);
    }

    // Render categories table
    renderCategoriesTable(maturity.by_category);

    // Populate category filter
    populateCategoryFilter(maturity.by_category);

    // Render subcategories table
    renderSubcategoriesTable(maturity.by_subcategory);

    // Render statistics
    renderStatistics(maturity.statistics);

    // Restore filter state from URL (for bookmarks/shared links)
    restoreUrlState();
}

function renderFunctionsGrid(functions) {
    const grid = document.getElementById('functions-grid');
    if (!grid) return;

    grid.innerHTML = '';

    for (const func of functions) {
        const card = document.createElement('div');
        card.className = 'function-card clickable';
        card.dataset.functionId = func.entity_id;
        card.title = `Click to filter by ${func.entity_id}`;

        card.innerHTML = `
            <div class="function-id">${escapeHtml(func.entity_id)}</div>
            <div class="function-name">${escapeHtml(func.display_name)}</div>
            <div class="function-score-display">${formatNumber(func.score)}</div>
            <div class="function-level-badge">Level ${func.level}</div>
        `;

        // Drill-down: click function to filter categories
        card.onclick = () => drillDownToFunction(func.entity_id);

        grid.appendChild(card);
    }
}

function renderCategoriesTable(categories) {
    const tbody = document.getElementById('categories-tbody');
    if (!tbody) return;

    tbody.innerHTML = '';

    const sortedKeys = Object.keys(categories).sort();

    for (const catId of sortedKeys) {
        const cat = categories[catId];
        const row = document.createElement('tr');
        row.dataset.categoryId = catId;
        row.className = 'clickable';
        row.title = `Click to filter subcategories by ${catId}`;

        const percentage = (cat.score / 4.0) * 100;

        row.innerHTML = `
            <td><strong>${escapeHtml(catId)}</strong></td>
            <td>${formatNumber(cat.score)}</td>
            <td>Level ${cat.level}</td>
            <td>
                <div class="bar-container" style="width: 100px; height: 16px;">
                    <div class="bar-fill" style="width: ${percentage}%"></div>
                </div>
            </td>
            <td>${cat.evidence_count || 0}</td>
        `;

        // Drill-down: click category to filter subcategories
        row.onclick = () => drillDownToCategory(catId);

        tbody.appendChild(row);
    }
}

function populateCategoryFilter(categories) {
    const select = document.getElementById('category-filter');
    if (!select) return;

    // Clear existing options except first
    while (select.options.length > 1) {
        select.remove(1);
    }

    const sortedKeys = Object.keys(categories).sort();
    for (const catId of sortedKeys) {
        const option = document.createElement('option');
        option.value = catId;
        option.textContent = catId;
        select.appendChild(option);
    }
}

function renderSubcategoriesTable(subcategories) {
    const tbody = document.getElementById('subcategories-tbody');
    if (!tbody) return;

    tbody.innerHTML = '';

    const sortedKeys = Object.keys(subcategories).sort();

    for (const subId of sortedKeys) {
        const sub = subcategories[subId];
        const row = document.createElement('tr');
        row.dataset.subcategoryId = subId;
        row.className = 'clickable';
        row.title = `Click to view ${subId} details and evidence`;

        // Color-code the level
        const levelClass = getLevelClass(sub.level);

        row.innerHTML = `
            <td><strong>${escapeHtml(subId)}</strong></td>
            <td>${formatNumber(sub.score)}</td>
            <td><span class="level-badge ${levelClass}">Level ${sub.level}</span></td>
            <td>${sub.evidence_count || 0}</td>
            <td>${formatNumber(sub.confidence * 100, 0)}%</td>
            <td class="action-cell"><button class="btn-icon" title="View details">&#128269;</button></td>
        `;

        // Click handler to show control details
        row.onclick = () => showControlDetail(subId);

        tbody.appendChild(row);
    }
}

/**
 * Get CSS class for maturity level coloring.
 */
function getLevelClass(level) {
    if (level === 0) return 'level-0';
    if (level === 1) return 'level-1';
    if (level === 2) return 'level-2';
    if (level === 3) return 'level-3';
    if (level === 4) return 'level-4';
    return '';
}

function renderStatistics(stats) {
    const grid = document.getElementById('stats-grid');
    if (!grid || !stats) return;

    grid.innerHTML = '';

    const statItems = [
        { label: 'Total Subcategories', value: stats.total_subcategories },
        { label: 'With Evidence', value: stats.subcategories_with_evidence },
        { label: 'Without Evidence', value: stats.subcategories_without_evidence },
        { label: 'Average Confidence', value: formatNumber(stats.average_confidence * 100, 0) + '%' }
    ];

    if (stats.level_distribution) {
        for (let i = 0; i <= 4; i++) {
            statItems.push({
                label: `Level ${i}`,
                value: stats.level_distribution[i] || 0
            });
        }
    }

    for (const item of statItems) {
        const card = document.createElement('div');
        card.className = 'stat-card';
        card.innerHTML = `
            <span class="stat-value">${item.value}</span>
            <span class="stat-label">${escapeHtml(item.label)}</span>
        `;
        grid.appendChild(card);
    }
}

function filterCategories() {
    const funcFilter = document.getElementById('function-filter').value;
    const rows = document.querySelectorAll('#categories-tbody tr');

    for (const row of rows) {
        const catId = row.dataset.categoryId;
        if (!funcFilter || catId.startsWith(funcFilter + '.')) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    }

    // Update URL with current filter state
    updateUrlState();
}

function filterSubcategories() {
    const catFilter = document.getElementById('category-filter').value;
    const levelFilter = document.getElementById('level-filter').value;
    const rows = document.querySelectorAll('#subcategories-tbody tr');

    for (const row of rows) {
        const subId = row.dataset.subcategoryId;
        let show = true;

        if (catFilter && !subId.startsWith(catFilter)) {
            show = false;
        }

        if (show && levelFilter && currentData.maturity) {
            const sub = currentData.maturity.by_subcategory[subId];
            if (sub && sub.level < parseInt(levelFilter)) {
                show = false;
            }
        }

        row.style.display = show ? '' : 'none';
    }

    // Update URL with current filter state
    updateUrlState();
}

// ============================================================================
// Drill-down Navigation
// ============================================================================

/**
 * Drill down from a function to its categories.
 * Sets the function filter, scrolls to categories section, and highlights.
 */
function drillDownToFunction(functionId) {
    const funcFilter = document.getElementById('function-filter');
    if (funcFilter) {
        funcFilter.value = functionId;
        filterCategories();
    }

    // Scroll to categories section
    const categoriesSection = document.querySelector('.categories-section');
    if (categoriesSection) {
        categoriesSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // Highlight the function card briefly
    highlightElement(`[data-function-id="${functionId}"]`);
}

/**
 * Drill down from a category to its subcategories.
 * Sets the category filter, scrolls to subcategories section.
 */
function drillDownToCategory(categoryId) {
    const catFilter = document.getElementById('category-filter');
    if (catFilter) {
        catFilter.value = categoryId;
        filterSubcategories();
    }

    // Scroll to subcategories section
    const subcategoriesSection = document.querySelector('.subcategories-section');
    if (subcategoriesSection) {
        subcategoriesSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // Highlight the category row briefly
    highlightElement(`tr[data-category-id="${categoryId}"]`);
}

/**
 * Briefly highlight an element to draw attention.
 */
function highlightElement(selector) {
    const el = document.querySelector(selector);
    if (!el) return;

    el.classList.add('drill-highlight');
    setTimeout(() => el.classList.remove('drill-highlight'), 1500);
}

// ============================================================================
// URL State Management (Bookmark/Share URLs)
// ============================================================================

/**
 * Update URL hash with current filter state.
 * Allows bookmarking and sharing filtered views.
 */
function updateUrlState() {
    const path = window.location.pathname;
    const params = new URLSearchParams();

    if (path === '/dashboard') {
        const funcFilter = document.getElementById('function-filter');
        const catFilter = document.getElementById('category-filter');
        const levelFilter = document.getElementById('level-filter');

        if (funcFilter && funcFilter.value) params.set('func', funcFilter.value);
        if (catFilter && catFilter.value) params.set('cat', catFilter.value);
        if (levelFilter && levelFilter.value) params.set('level', levelFilter.value);
    } else if (path === '/gaps') {
        const priorityFilter = document.getElementById('priority-filter');
        const functionFilter = document.getElementById('function-filter');
        const typeFilter = document.getElementById('type-filter');

        if (priorityFilter && priorityFilter.value) params.set('priority', priorityFilter.value);
        if (functionFilter && functionFilter.value) params.set('func', functionFilter.value);
        if (typeFilter && typeFilter.value) params.set('type', typeFilter.value);
    } else if (path === '/evidence') {
        const platformFilter = document.getElementById('platform-filter');
        const typeFilter = document.getElementById('type-filter');

        if (platformFilter && platformFilter.value) params.set('platform', platformFilter.value);
        if (typeFilter && typeFilter.value) params.set('type', typeFilter.value);
    }

    // Update URL without triggering navigation
    const newUrl = params.toString() ? `${path}?${params.toString()}` : path;
    history.replaceState(null, '', newUrl);
}

/**
 * Restore filter state from URL query parameters.
 * Called on page load to restore bookmarked/shared state.
 */
function restoreUrlState() {
    const params = new URLSearchParams(window.location.search);
    const path = window.location.pathname;

    if (path === '/dashboard') {
        const funcValue = params.get('func');
        const catValue = params.get('cat');
        const levelValue = params.get('level');

        if (funcValue) {
            const funcFilter = document.getElementById('function-filter');
            if (funcFilter) funcFilter.value = funcValue;
        }
        if (catValue) {
            const catFilter = document.getElementById('category-filter');
            if (catFilter) catFilter.value = catValue;
        }
        if (levelValue) {
            const levelFilter = document.getElementById('level-filter');
            if (levelFilter) levelFilter.value = levelValue;
        }

        // Apply filters if any were set
        if (funcValue || catValue || levelValue) {
            filterCategories();
            filterSubcategories();
        }
    } else if (path === '/gaps') {
        const priorityValue = params.get('priority');
        const funcValue = params.get('func');
        const typeValue = params.get('type');

        if (priorityValue) {
            const priorityFilter = document.getElementById('priority-filter');
            if (priorityFilter) priorityFilter.value = priorityValue;
        }
        if (funcValue) {
            const functionFilter = document.getElementById('function-filter');
            if (functionFilter) functionFilter.value = funcValue;
        }
        if (typeValue) {
            const typeFilter = document.getElementById('type-filter');
            if (typeFilter) typeFilter.value = typeValue;
        }

        // Apply filters if any were set
        if (priorityValue || funcValue || typeValue) {
            filterGaps();
        }
    } else if (path === '/evidence') {
        const platformValue = params.get('platform');
        const typeValue = params.get('type');

        if (platformValue) {
            const platformFilter = document.getElementById('platform-filter');
            if (platformFilter) platformFilter.value = platformValue;
        }
        if (typeValue) {
            const typeFilter = document.getElementById('type-filter');
            if (typeFilter) typeFilter.value = typeValue;
        }

        // Apply filters if any were set
        if (platformValue || typeValue) {
            filterEvidence();
        }
    }
}

// ============================================================================
// Gaps Page
// ============================================================================

async function loadGapsData() {
    const gaps = await fetchJson('/api/gaps');

    if (!gaps || gaps.error) {
        document.getElementById('total-gaps').textContent = '0';
        return;
    }

    currentData.gaps = gaps;

    // Update summary stats
    document.getElementById('total-gaps').textContent = gaps.controls_with_gaps || 0;
    document.getElementById('critical-gaps').textContent = gaps.gaps_by_priority?.critical || 0;
    document.getElementById('high-gaps').textContent = gaps.gaps_by_priority?.high || 0;
    document.getElementById('medium-gaps').textContent = gaps.gaps_by_priority?.medium || 0;
    document.getElementById('low-gaps').textContent = gaps.gaps_by_priority?.low || 0;

    // Render quick wins
    renderQuickWins(gaps.quick_wins);

    // Render critical gaps
    renderCriticalGaps(gaps.critical_gaps);

    // Render all gaps table
    renderGapsTable(gaps.all_gaps);

    // Render recommendations
    renderRecommendations(gaps.top_recommendations);

    // Restore filter state from URL (for bookmarks/shared links)
    restoreUrlState();
}

function renderQuickWins(quickWins) {
    const container = document.getElementById('quick-wins-list');
    if (!container) return;

    container.innerHTML = '';

    if (!quickWins || quickWins.length === 0) {
        container.innerHTML = '<p class="section-desc">No quick wins identified.</p>';
        return;
    }

    for (const gap of quickWins.slice(0, 5)) {
        const item = document.createElement('div');
        item.className = 'gap-item';
        item.innerHTML = `
            <div class="gap-info">
                <div class="gap-control-id">${escapeHtml(gap.control_id)}: ${escapeHtml(gap.control_name)}</div>
                <div class="gap-explanation">${escapeHtml(gap.explanation?.substring(0, 150))}...</div>
            </div>
            <span class="gap-priority priority-${gap.priority}">${gap.priority}</span>
        `;
        item.onclick = () => showGapDetails(gap);
        container.appendChild(item);
    }
}

function renderCriticalGaps(criticalGaps) {
    const container = document.getElementById('critical-gaps-list');
    if (!container) return;

    container.innerHTML = '';

    if (!criticalGaps || criticalGaps.length === 0) {
        container.innerHTML = '<p class="section-desc">No critical gaps identified.</p>';
        return;
    }

    for (const gap of criticalGaps.slice(0, 5)) {
        const item = document.createElement('div');
        item.className = 'gap-item';
        item.innerHTML = `
            <div class="gap-info">
                <div class="gap-control-id">${escapeHtml(gap.control_id)}: ${escapeHtml(gap.control_name)}</div>
                <div class="gap-explanation">${escapeHtml(gap.explanation?.substring(0, 150))}...</div>
            </div>
            <span class="gap-priority priority-critical">CRITICAL</span>
        `;
        item.onclick = () => showGapDetails(gap);
        container.appendChild(item);
    }
}

function renderGapsTable(gaps) {
    const tbody = document.getElementById('gaps-tbody');
    if (!tbody) return;

    tbody.innerHTML = '';

    if (!gaps || gaps.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6">No gaps found.</td></tr>';
        return;
    }

    for (const gap of gaps) {
        const row = document.createElement('tr');
        row.dataset.gapId = gap.control_id;
        row.dataset.priority = gap.priority;
        row.dataset.function = gap.function_id;
        row.dataset.type = gap.gap_type;

        row.innerHTML = `
            <td><strong>${escapeHtml(gap.control_id)}</strong></td>
            <td><span class="gap-priority priority-${gap.priority}">${gap.priority}</span></td>
            <td>${escapeHtml(gap.gap_type?.replace('_', ' '))}</td>
            <td>Level ${gap.current_maturity}</td>
            <td>Level ${gap.target_maturity}</td>
            <td><button class="btn btn-secondary" onclick="showGapDetails(currentData.gaps.all_gaps.find(g => g.control_id === '${gap.control_id}'))">Details</button></td>
        `;

        tbody.appendChild(row);
    }
}

function renderRecommendations(recommendations) {
    const container = document.getElementById('recommendations-list');
    if (!container) return;

    container.innerHTML = '';

    if (!recommendations || recommendations.length === 0) {
        container.innerHTML = '<p class="section-desc">No recommendations available.</p>';
        return;
    }

    for (const rec of recommendations.slice(0, 10)) {
        const item = document.createElement('div');
        item.className = 'recommendation-item';
        item.innerHTML = `
            <div class="gap-info">
                <div class="gap-control-id">${escapeHtml(rec.action)}</div>
                <div class="gap-explanation">
                    ${rec.platform ? `Platform: ${escapeHtml(rec.platform)} | ` : ''}
                    Effort: ${escapeHtml(rec.effort)} | Impact: ${escapeHtml(rec.impact)}
                </div>
            </div>
        `;
        container.appendChild(item);
    }
}

function filterGaps() {
    const priorityFilter = document.getElementById('priority-filter').value;
    const functionFilter = document.getElementById('function-filter').value;
    const typeFilter = document.getElementById('type-filter').value;

    const rows = document.querySelectorAll('#gaps-tbody tr');

    for (const row of rows) {
        let show = true;

        if (priorityFilter && row.dataset.priority !== priorityFilter) {
            show = false;
        }
        if (functionFilter && row.dataset.function !== functionFilter) {
            show = false;
        }
        if (typeFilter && row.dataset.type !== typeFilter) {
            show = false;
        }

        row.style.display = show ? '' : 'none';
    }

    // Update URL with current filter state
    updateUrlState();
}

function sortGaps(column) {
    if (sortState.column === column) {
        sortState.ascending = !sortState.ascending;
    } else {
        sortState.column = column;
        sortState.ascending = true;
    }

    if (currentData.gaps && currentData.gaps.all_gaps) {
        const sorted = [...currentData.gaps.all_gaps].sort((a, b) => {
            let valA = a[column];
            let valB = b[column];

            if (typeof valA === 'string') {
                valA = valA.toLowerCase();
                valB = valB.toLowerCase();
            }

            if (valA < valB) return sortState.ascending ? -1 : 1;
            if (valA > valB) return sortState.ascending ? 1 : -1;
            return 0;
        });

        renderGapsTable(sorted);
    }
}

function showGapDetails(gap) {
    if (!gap) return;

    const modal = document.getElementById('gap-modal');
    const title = document.getElementById('modal-title');
    const body = document.getElementById('modal-body');

    title.textContent = `${gap.control_id}: ${gap.control_name}`;

    let recommendationsHtml = '';
    if (gap.recommendations && gap.recommendations.length > 0) {
        recommendationsHtml = '<h4>Recommendations:</h4><ul>';
        for (const rec of gap.recommendations) {
            recommendationsHtml += `<li><strong>${escapeHtml(rec.action)}</strong><br>
                ${escapeHtml(rec.details)}<br>
                <small>Platform: ${escapeHtml(rec.platform || 'Any')} | Effort: ${escapeHtml(rec.effort)} | Impact: ${escapeHtml(rec.impact)}</small>
            </li>`;
        }
        recommendationsHtml += '</ul>';
    }

    body.innerHTML = `
        <p><strong>Priority:</strong> <span class="gap-priority priority-${gap.priority}">${gap.priority}</span></p>
        <p><strong>Gap Type:</strong> ${escapeHtml(gap.gap_type?.replace('_', ' '))}</p>
        <p><strong>Current Maturity:</strong> Level ${gap.current_maturity}</p>
        <p><strong>Target Maturity:</strong> Level ${gap.target_maturity}</p>
        <p><strong>Function:</strong> ${escapeHtml(gap.function_id)} - ${FUNCTION_NAMES[gap.function_id] || ''}</p>
        <p><strong>Category:</strong> ${escapeHtml(gap.category_id)}</p>
        ${gap.evidence_age_days ? `<p><strong>Evidence Age:</strong> ${gap.evidence_age_days} days</p>` : ''}
        <hr>
        <p><strong>Explanation:</strong></p>
        <p>${escapeHtml(gap.explanation)}</p>
        ${recommendationsHtml}
    `;

    modal.style.display = 'flex';
}

function closeModal() {
    const modals = document.querySelectorAll('.modal');
    for (const modal of modals) {
        modal.style.display = 'none';
    }
}

// Close modal on outside click
window.onclick = function(event) {
    if (event.target.classList.contains('modal')) {
        closeModal();
    }
};

// Close modal on escape key
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        closeModal();
    }
});

// ============================================================================
// Evidence Page
// ============================================================================

async function loadEvidenceData() {
    const evidence = await fetchJson('/api/evidence');

    if (!evidence || evidence.error) {
        document.getElementById('total-evidence').textContent = '0';
        return;
    }

    currentData.evidence = evidence;

    // Update stats
    document.getElementById('total-evidence').textContent = evidence.total || 0;
    document.getElementById('platforms-count').textContent = evidence.filters?.platforms?.length || 0;
    document.getElementById('types-count').textContent = evidence.filters?.evidence_types?.length || 0;

    // Populate filters
    populateEvidenceFilters(evidence.filters);

    // Render platform grid
    renderPlatformGrid(evidence.evidence);

    // Render evidence table
    renderEvidenceTable(evidence.evidence);

    // Restore filter state from URL (for bookmarks/shared links)
    restoreUrlState();
}

function populateEvidenceFilters(filters) {
    if (!filters) return;

    const platformSelect = document.getElementById('platform-filter');
    const typeSelect = document.getElementById('type-filter');

    if (platformSelect && filters.platforms) {
        while (platformSelect.options.length > 1) {
            platformSelect.remove(1);
        }
        for (const platform of filters.platforms) {
            const option = document.createElement('option');
            option.value = platform;
            option.textContent = platform;
            platformSelect.appendChild(option);
        }
    }

    if (typeSelect && filters.evidence_types) {
        while (typeSelect.options.length > 1) {
            typeSelect.remove(1);
        }
        for (const type of filters.evidence_types) {
            const option = document.createElement('option');
            option.value = type;
            option.textContent = type.replace(/_/g, ' ');
            typeSelect.appendChild(option);
        }
    }
}

function renderPlatformGrid(evidence) {
    const grid = document.getElementById('platform-grid');
    if (!grid) return;

    grid.innerHTML = '';

    // Count by platform
    const platformCounts = {};
    for (const ev of evidence || []) {
        const platform = ev.platform || 'unknown';
        platformCounts[platform] = (platformCounts[platform] || 0) + 1;
    }

    for (const [platform, count] of Object.entries(platformCounts)) {
        const card = document.createElement('div');
        card.className = 'platform-card';
        card.innerHTML = `
            <div class="platform-name">${escapeHtml(platform)}</div>
            <div class="platform-count">${count}</div>
        `;
        grid.appendChild(card);
    }

    if (Object.keys(platformCounts).length === 0) {
        grid.innerHTML = '<p>No evidence collected yet.</p>';
    }
}

function renderEvidenceTable(evidence) {
    const tbody = document.getElementById('evidence-tbody');
    if (!tbody) return;

    tbody.innerHTML = '';

    if (!evidence || evidence.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5">No evidence found.</td></tr>';
        return;
    }

    for (const ev of evidence) {
        const row = document.createElement('tr');
        row.dataset.platform = ev.platform;
        row.dataset.type = ev.evidence_type;

        row.innerHTML = `
            <td>${escapeHtml(ev.platform)}</td>
            <td>${escapeHtml(ev.evidence_type?.replace(/_/g, ' '))}</td>
            <td>${formatDate(ev.collected_at)}</td>
            <td><code>${escapeHtml(ev.file_hash?.substring(0, 16))}...</code></td>
            <td><button class="btn btn-secondary" onclick="showEvidenceDetails('${ev.id}')">View</button></td>
        `;

        tbody.appendChild(row);
    }

    updatePagination();
}

function filterEvidence() {
    const platformFilter = document.getElementById('platform-filter').value;
    const typeFilter = document.getElementById('type-filter').value;

    const rows = document.querySelectorAll('#evidence-tbody tr');

    for (const row of rows) {
        let show = true;

        if (platformFilter && row.dataset.platform !== platformFilter) {
            show = false;
        }
        if (typeFilter && row.dataset.type !== typeFilter) {
            show = false;
        }

        row.style.display = show ? '' : 'none';
    }

    // Update URL with current filter state
    updateUrlState();
}

async function refreshEvidence() {
    await loadEvidenceData();
}

function sortEvidence(column) {
    // Similar to sortGaps
    if (currentData.evidence && currentData.evidence.evidence) {
        const sorted = [...currentData.evidence.evidence].sort((a, b) => {
            let valA = a[column];
            let valB = b[column];

            if (typeof valA === 'string') {
                valA = valA.toLowerCase();
                valB = valB.toLowerCase();
            }

            if (sortState.column === column && !sortState.ascending) {
                return valB > valA ? 1 : -1;
            }
            return valA > valB ? 1 : -1;
        });

        sortState.column = column;
        sortState.ascending = !sortState.ascending;

        renderEvidenceTable(sorted);
    }
}

function updatePagination() {
    const pageInfo = document.getElementById('page-info');
    if (pageInfo) {
        pageInfo.textContent = `Page ${paginationState.page}`;
    }
}

function prevPage() {
    if (paginationState.page > 1) {
        paginationState.page--;
        loadEvidenceData();
    }
}

function nextPage() {
    paginationState.page++;
    loadEvidenceData();
}

function showEvidenceDetails(evidenceId) {
    const modal = document.getElementById('evidence-modal');
    const title = document.getElementById('modal-title');
    const body = document.getElementById('modal-body');

    const evidence = currentData.evidence?.evidence?.find(e => e.id === evidenceId);

    if (!evidence) {
        body.innerHTML = '<p>Evidence not found.</p>';
        modal.style.display = 'flex';
        return;
    }

    title.textContent = `Evidence: ${evidence.evidence_type}`;

    body.innerHTML = `
        <p><strong>ID:</strong> ${escapeHtml(evidence.id)}</p>
        <p><strong>Platform:</strong> ${escapeHtml(evidence.platform)}</p>
        <p><strong>Type:</strong> ${escapeHtml(evidence.evidence_type)}</p>
        <p><strong>Collected:</strong> ${formatDate(evidence.collected_at)}</p>
        <p><strong>Hash:</strong> <code>${escapeHtml(evidence.file_hash)}</code></p>
        ${evidence.metadata ? `<p><strong>Metadata:</strong></p><pre>${escapeHtml(JSON.stringify(evidence.metadata, null, 2))}</pre>` : ''}
    `;

    modal.style.display = 'flex';
}

// ============================================================================
// Trends Page
// ============================================================================

async function loadTrendsData() {
    const trends = await fetchJson('/api/trends');

    if (!trends || trends.error) {
        document.getElementById('overall-direction').textContent = 'N/A';
        document.getElementById('trend-delta').textContent = 'N/A';
        return;
    }

    currentData.trends = trends;

    // Update summary
    const direction = trends.overall_trend?.direction || 'stable';
    document.getElementById('overall-direction').textContent = direction.charAt(0).toUpperCase() + direction.slice(1);

    const delta = trends.overall_trend?.score_delta;
    if (delta !== null && delta !== undefined) {
        const sign = delta > 0 ? '+' : '';
        document.getElementById('trend-delta').textContent = sign + formatNumber(delta);
    }

    document.getElementById('trend-period').textContent = `${trends.period_days} days`;

    // Render trend chart
    renderTrendChart(trends.chart_data?.overall_line);

    // Render function trends
    renderFunctionTrends(trends.function_trends);

    // Update change counts
    document.getElementById('improving-count').textContent = trends.improving_controls?.length || 0;
    document.getElementById('stable-count').textContent = trends.stable_controls?.length || 0;
    document.getElementById('regressing-count').textContent = trends.regressing_controls?.length || 0;
    document.getElementById('volatile-count').textContent = trends.volatile_controls?.length || 0;

    // Render control lists
    renderTrendControlsList('improving-list', trends.improving_controls);
    renderTrendControlsList('regressing-list', trends.regressing_controls);

    // Render statistics
    renderTrendStatistics(trends.statistics);
}

function renderTrendChart(chartData) {
    const canvas = document.getElementById('overall-trend-chart');
    if (!canvas || !chartData) return;

    const ctx = canvas.getContext('2d');
    const labels = chartData.labels || [];
    const datasets = chartData.datasets || [];

    if (labels.length === 0 || datasets.length === 0) {
        ctx.fillStyle = '#666666';
        ctx.font = '14px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('Insufficient data for chart', canvas.width / 2, canvas.height / 2);
        return;
    }

    const data = datasets[0]?.data || [];

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Calculate dimensions
    const padding = 50;
    const chartWidth = canvas.width - padding * 2;
    const chartHeight = canvas.height - padding * 2;

    // Calculate scales
    const maxValue = Math.max(...data, 4);
    const minValue = Math.min(...data, 0);
    const valueRange = maxValue - minValue;

    // Draw axes
    ctx.strokeStyle = '#CCCCCC';
    ctx.lineWidth = 1;

    // Y axis
    ctx.beginPath();
    ctx.moveTo(padding, padding);
    ctx.lineTo(padding, canvas.height - padding);
    ctx.stroke();

    // X axis
    ctx.beginPath();
    ctx.moveTo(padding, canvas.height - padding);
    ctx.lineTo(canvas.width - padding, canvas.height - padding);
    ctx.stroke();

    // Draw Y axis labels
    ctx.fillStyle = '#666666';
    ctx.font = '12px sans-serif';
    ctx.textAlign = 'right';

    for (let i = 0; i <= 4; i++) {
        const y = canvas.height - padding - (i / 4) * chartHeight;
        ctx.fillText(i.toString(), padding - 10, y + 4);

        // Grid line
        ctx.strokeStyle = '#EEEEEE';
        ctx.beginPath();
        ctx.moveTo(padding, y);
        ctx.lineTo(canvas.width - padding, y);
        ctx.stroke();
    }

    // Draw data line
    if (data.length > 1) {
        ctx.strokeStyle = '#333333';
        ctx.lineWidth = 2;
        ctx.beginPath();

        for (let i = 0; i < data.length; i++) {
            const x = padding + (i / (data.length - 1)) * chartWidth;
            const y = canvas.height - padding - ((data[i] - minValue) / 4) * chartHeight;

            if (i === 0) {
                ctx.moveTo(x, y);
            } else {
                ctx.lineTo(x, y);
            }
        }
        ctx.stroke();

        // Draw data points
        ctx.fillStyle = '#333333';
        for (let i = 0; i < data.length; i++) {
            const x = padding + (i / (data.length - 1)) * chartWidth;
            const y = canvas.height - padding - ((data[i] - minValue) / 4) * chartHeight;

            ctx.beginPath();
            ctx.arc(x, y, 4, 0, Math.PI * 2);
            ctx.fill();
        }
    }

    // Draw X axis labels (show first, middle, last)
    ctx.fillStyle = '#666666';
    ctx.textAlign = 'center';

    if (labels.length > 0) {
        ctx.fillText(labels[0], padding, canvas.height - padding + 20);
    }
    if (labels.length > 2) {
        const midIdx = Math.floor(labels.length / 2);
        const midX = padding + (midIdx / (labels.length - 1)) * chartWidth;
        ctx.fillText(labels[midIdx], midX, canvas.height - padding + 20);
    }
    if (labels.length > 1) {
        ctx.fillText(labels[labels.length - 1], canvas.width - padding, canvas.height - padding + 20);
    }
}

function renderFunctionTrends(functionTrends) {
    const grid = document.getElementById('function-trends-grid');
    if (!grid || !functionTrends) return;

    grid.innerHTML = '';

    const functionOrder = ['GV', 'ID', 'PR', 'DE', 'RS', 'RC'];

    for (const funcId of functionOrder) {
        const trend = functionTrends[funcId];
        if (!trend) continue;

        const card = document.createElement('div');
        card.className = 'function-trend-card';

        const deltaStr = trend.score_delta !== null ?
            (trend.score_delta > 0 ? '+' : '') + formatNumber(trend.score_delta) : 'N/A';

        card.innerHTML = `
            <div class="function-trend-header">
                <span class="function-trend-name">${funcId} - ${FUNCTION_NAMES[funcId] || funcId}</span>
                <span class="function-trend-direction">${escapeHtml(trend.direction)}</span>
            </div>
            <div class="function-trend-score">${formatNumber(trend.current_score)}</div>
            <div class="function-trend-delta">Change: ${deltaStr}</div>
        `;

        grid.appendChild(card);
    }
}

function renderTrendControlsList(containerId, controls) {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.innerHTML = '';

    if (!controls || controls.length === 0) {
        container.innerHTML = '<p class="section-desc">None identified.</p>';
        return;
    }

    for (const control of controls.slice(0, 10)) {
        const item = document.createElement('div');
        item.className = 'control-item';

        const deltaStr = control.score_delta !== null ?
            (control.score_delta > 0 ? '+' : '') + formatNumber(control.score_delta) : '';

        item.innerHTML = `
            <span class="control-id">${escapeHtml(control.entity_id)}</span>
            <span class="control-delta">${deltaStr}</span>
        `;

        container.appendChild(item);
    }
}

function renderTrendStatistics(stats) {
    const grid = document.getElementById('trend-stats');
    if (!grid || !stats) return;

    grid.innerHTML = '';

    const statItems = [
        { label: 'Controls Analyzed', value: stats.total_controls_analyzed },
        { label: 'Snapshots Analyzed', value: stats.snapshots_analyzed },
        { label: 'Improving %', value: formatNumber(stats.improving_percentage, 1) + '%' },
        { label: 'Regressing %', value: formatNumber(stats.regressing_percentage, 1) + '%' },
        { label: 'Average Score', value: formatNumber(stats.average_overall_score) },
        { label: 'Min Score', value: formatNumber(stats.min_overall_score) },
        { label: 'Max Score', value: formatNumber(stats.max_overall_score) }
    ];

    for (const item of statItems) {
        const card = document.createElement('div');
        card.className = 'stat-card';
        card.innerHTML = `
            <span class="stat-value">${item.value}</span>
            <span class="stat-label">${escapeHtml(item.label)}</span>
        `;
        grid.appendChild(card);
    }
}

// ============================================================================
// Auto-Refresh Functions
// ============================================================================

/**
 * Start auto-refresh with specified interval.
 * @param {number} seconds - Refresh interval in seconds (default: 60)
 */
function startAutoRefresh(seconds = 60) {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
    }

    autoRefreshSeconds = seconds;
    autoRefreshEnabled = true;

    autoRefreshInterval = setInterval(() => {
        refreshCurrentPage();
    }, seconds * 1000);

    updateRefreshUI();
    console.log(`Auto-refresh started: every ${seconds} seconds`);
}

/**
 * Stop auto-refresh.
 */
function stopAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
    }
    autoRefreshEnabled = false;
    updateRefreshUI();
    console.log('Auto-refresh stopped');
}

/**
 * Toggle auto-refresh on/off.
 */
function toggleAutoRefresh() {
    if (autoRefreshEnabled) {
        stopAutoRefresh();
    } else {
        startAutoRefresh(autoRefreshSeconds);
    }
}

/**
 * Refresh the current page's data.
 */
function refreshCurrentPage() {
    const path = window.location.pathname;

    // Update last refresh time
    lastRefreshTime = new Date();
    updateLastRefreshDisplay();

    // Call appropriate load function based on current page
    if (path === '/' || path === '/index') {
        loadIndexData();
    } else if (path === '/dashboard') {
        loadDashboardData();
    } else if (path === '/gaps') {
        loadGapsData();
    } else if (path === '/evidence') {
        loadEvidenceData();
    } else if (path === '/trends') {
        loadTrendsData();
    }
}

/**
 * Update the last refresh timestamp display.
 */
function updateLastRefreshDisplay() {
    const el = document.getElementById('last-refresh');
    if (!el) return;

    if (lastRefreshTime) {
        const timeStr = lastRefreshTime.toLocaleTimeString();
        el.textContent = `Last refresh: ${timeStr}`;
    } else {
        el.textContent = 'Last refresh: --:--:--';
    }
}

/**
 * Update the auto-refresh button UI.
 */
function updateRefreshUI() {
    const btn = document.getElementById('auto-refresh-btn');
    if (!btn) return;

    if (autoRefreshEnabled) {
        btn.textContent = `Auto: ${autoRefreshSeconds}s`;
        btn.classList.add('active');
    } else {
        btn.textContent = 'Auto: Off';
        btn.classList.remove('active');
    }
}

/**
 * Initialize refresh controls on page load.
 */
function initRefreshControls() {
    // Set initial last refresh time
    lastRefreshTime = new Date();
    updateLastRefreshDisplay();
    updateRefreshUI();
}

// ============================================================================
// Global Search
// ============================================================================

let searchResults = [];
let selectedResultIndex = -1;

/**
 * Initialize global search functionality.
 */
function initGlobalSearch() {
    const searchInput = document.getElementById('global-search-input');
    const resultsContainer = document.getElementById('search-results');

    if (!searchInput) return;

    // Handle input changes with debounce
    let debounceTimeout;
    searchInput.addEventListener('input', function(e) {
        clearTimeout(debounceTimeout);
        debounceTimeout = setTimeout(() => handleSearchInput(e), 150);
    });

    // Handle keyboard navigation
    searchInput.addEventListener('keydown', handleSearchKeydown);

    // Close results on outside click
    document.addEventListener('click', function(e) {
        if (!e.target.closest('.global-search')) {
            hideSearchResults();
        }
    });

    // Global keyboard shortcut (Ctrl+K or /)
    document.addEventListener('keydown', function(e) {
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            searchInput.focus();
            searchInput.select();
        } else if (e.key === '/' && !isInputFocused()) {
            e.preventDefault();
            searchInput.focus();
        } else if (e.key === 'Escape') {
            hideSearchResults();
            searchInput.blur();
        }
    });

    // Pre-load data for search
    preloadSearchData();
}

/**
 * Handle search input changes.
 */
function handleSearchInput(e) {
    const query = e.target.value.trim().toLowerCase();

    if (query.length < 2) {
        hideSearchResults();
        return;
    }

    searchResults = performSearch(query);
    renderSearchResults(searchResults);
}

/**
 * Perform search across all data sources.
 */
function performSearch(query) {
    const results = [];
    const maxPerCategory = 5;

    // Search controls (from maturity)
    if (currentData.maturity && currentData.maturity.by_subcategory) {
        const controlMatches = [];
        for (const [id, data] of Object.entries(currentData.maturity.by_subcategory)) {
            const name = data.name || data.entity_id || id;
            const searchText = `${id} ${name}`.toLowerCase();
            if (searchText.includes(query)) {
                controlMatches.push({
                    type: 'control',
                    id: id,
                    title: id,
                    subtitle: `Level ${data.level || 0} - Score ${formatNumber(data.score || 0)}`,
                    page: '/dashboard',
                    hash: id,
                });
            }
            if (controlMatches.length >= maxPerCategory) break;
        }
        results.push(...controlMatches);
    }

    // Search gaps
    if (currentData.gaps && currentData.gaps.all_gaps) {
        const gapMatches = [];
        for (const gap of currentData.gaps.all_gaps) {
            const searchText = `${gap.control_id || ''} ${gap.control_name || ''} ${gap.explanation || ''}`.toLowerCase();
            if (searchText.includes(query)) {
                gapMatches.push({
                    type: 'gap',
                    id: gap.control_id,
                    title: `${gap.control_id}: ${gap.control_name || 'Gap'}`,
                    subtitle: `${gap.priority || 'unknown'} priority - ${gap.gap_type || 'unknown'}`,
                    page: '/gaps',
                    hash: gap.control_id,
                });
            }
            if (gapMatches.length >= maxPerCategory) break;
        }
        results.push(...gapMatches);
    }

    // Search evidence
    if (currentData.evidence && currentData.evidence.evidence) {
        const evidenceMatches = [];
        for (const ev of currentData.evidence.evidence) {
            const searchText = `${ev.platform || ''} ${ev.evidence_type || ''}`.toLowerCase();
            if (searchText.includes(query)) {
                evidenceMatches.push({
                    type: 'evidence',
                    id: ev.id,
                    title: `${ev.platform}: ${ev.evidence_type}`,
                    subtitle: `Collected ${formatDate(ev.collected_at)}`,
                    page: '/evidence',
                    hash: ev.id,
                });
            }
            if (evidenceMatches.length >= maxPerCategory) break;
        }
        results.push(...evidenceMatches);
    }

    return results;
}

/**
 * Render search results in dropdown.
 */
function renderSearchResults(results) {
    const container = document.getElementById('search-results');
    if (!container) return;

    container.innerHTML = '';
    selectedResultIndex = -1;

    if (results.length === 0) {
        container.innerHTML = '<div class="search-no-results">No results found</div>';
        container.classList.add('visible');
        return;
    }

    // Group by type
    const grouped = {
        control: [],
        gap: [],
        evidence: [],
    };

    for (const result of results) {
        if (grouped[result.type]) {
            grouped[result.type].push(result);
        }
    }

    const typeLabels = {
        control: 'Controls',
        gap: 'Gaps',
        evidence: 'Evidence',
    };

    let index = 0;
    for (const [type, items] of Object.entries(grouped)) {
        if (items.length === 0) continue;

        const section = document.createElement('div');
        section.className = 'search-section';
        section.innerHTML = `<div class="search-section-header">${typeLabels[type]}</div>`;

        for (const item of items) {
            const resultEl = document.createElement('div');
            resultEl.className = 'search-result';
            resultEl.dataset.index = index;
            resultEl.innerHTML = `
                <div class="search-result-title">${escapeHtml(item.title)}</div>
                <div class="search-result-subtitle">${escapeHtml(item.subtitle)}</div>
            `;
            resultEl.onclick = () => navigateToResult(item);
            section.appendChild(resultEl);
            index++;
        }

        container.appendChild(section);
    }

    container.classList.add('visible');
}

/**
 * Handle keyboard navigation in search results.
 */
function handleSearchKeydown(e) {
    const results = document.querySelectorAll('.search-result');
    if (results.length === 0 && e.key !== 'Enter') return;

    if (e.key === 'ArrowDown') {
        e.preventDefault();
        selectedResultIndex = Math.min(selectedResultIndex + 1, results.length - 1);
        updateSelectedResult(results);
    } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        selectedResultIndex = Math.max(selectedResultIndex - 1, 0);
        updateSelectedResult(results);
    } else if (e.key === 'Enter') {
        e.preventDefault();
        if (selectedResultIndex >= 0 && searchResults[selectedResultIndex]) {
            navigateToResult(searchResults[selectedResultIndex]);
        }
    }
}

/**
 * Update visual selection state.
 */
function updateSelectedResult(results) {
    results.forEach((el, i) => {
        el.classList.toggle('selected', i === selectedResultIndex);
    });
    if (selectedResultIndex >= 0 && results[selectedResultIndex]) {
        results[selectedResultIndex].scrollIntoView({ block: 'nearest' });
    }
}

/**
 * Navigate to a search result.
 */
function navigateToResult(result) {
    hideSearchResults();

    // Clear search input
    const input = document.getElementById('global-search-input');
    if (input) input.value = '';

    // Navigate with hash for highlighting
    const url = `${result.page}#${result.hash}`;
    window.location.href = url;
}

/**
 * Hide search results dropdown.
 */
function hideSearchResults() {
    const container = document.getElementById('search-results');
    if (container) {
        container.classList.remove('visible');
    }
    selectedResultIndex = -1;
}

/**
 * Check if current focus is in an input.
 */
function isInputFocused() {
    const active = document.activeElement;
    return active && (active.tagName === 'INPUT' || active.tagName === 'TEXTAREA' || active.isContentEditable);
}

/**
 * Pre-load all data for search functionality.
 */
async function preloadSearchData() {
    try {
        // Load data that isn't already loaded
        if (!currentData.maturity) {
            currentData.maturity = await fetchJson('/api/maturity');
        }
        if (!currentData.gaps) {
            currentData.gaps = await fetchJson('/api/gaps');
        }
        if (!currentData.evidence) {
            currentData.evidence = await fetchJson('/api/evidence?limit=500');
        }
    } catch (e) {
        // Silently fail - search will work with whatever data is available
        console.warn('Could not preload search data:', e);
    }
}

/**
 * Handle URL hash for highlighting items after navigation.
 */
function handleHashHighlight() {
    const hash = window.location.hash.slice(1);
    if (!hash) return;

    // Wait for data to load and render
    setTimeout(() => {
        // Try to find and highlight table rows
        const rows = document.querySelectorAll('tbody tr');
        for (const row of rows) {
            // Check various data attributes
            const rowId = row.dataset.gapId || row.dataset.subcategoryId || row.dataset.evidenceId || row.dataset.controlId;
            if (rowId === hash) {
                row.classList.add('highlighted');
                row.scrollIntoView({ behavior: 'smooth', block: 'center' });
                // Remove highlight class after animation completes
                setTimeout(() => row.classList.remove('highlighted'), 3000);
                return;
            }

            // Also check cell content
            const cells = row.querySelectorAll('td');
            for (const cell of cells) {
                if (cell.textContent.trim() === hash) {
                    row.classList.add('highlighted');
                    row.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    setTimeout(() => row.classList.remove('highlighted'), 3000);
                    return;
                }
            }
        }

        // Clear hash after processing
        history.replaceState(null, '', window.location.pathname);
    }, 500);
}

// ============================================================================
// Dark Mode
// ============================================================================

/**
 * Initialize dark mode based on saved preference.
 * Checks localStorage for 'nisify-theme' key.
 */
function initDarkMode() {
    const savedTheme = localStorage.getItem('nisify-theme');
    if (savedTheme === 'dark') {
        document.body.classList.add('dark-mode');
    }
    updateDarkModeButton();
}

/**
 * Toggle dark mode on/off.
 */
function toggleDarkMode() {
    document.body.classList.toggle('dark-mode');
    const isDark = document.body.classList.contains('dark-mode');
    localStorage.setItem('nisify-theme', isDark ? 'dark' : 'light');
    updateDarkModeButton();
}

/**
 * Update the dark mode toggle button text and title.
 */
function updateDarkModeButton() {
    const btn = document.getElementById('dark-mode-btn');
    if (!btn) return;

    const isDark = document.body.classList.contains('dark-mode');
    btn.textContent = isDark ? '\u2600' : '\u263D';  // Sun or Moon symbol
    btn.title = isDark ? 'Switch to light mode' : 'Switch to dark mode';
}

// ============================================================================
// Data Export Functions
// ============================================================================

/**
 * Export data as a downloadable file.
 * @param {string} data - The data to export
 * @param {string} filename - The filename for the download
 * @param {string} mimeType - The MIME type of the file
 */
function downloadFile(data, filename, mimeType) {
    const blob = new Blob([data], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

/**
 * Convert array of objects to CSV string.
 * @param {Array} data - Array of objects to convert
 * @param {Array} columns - Column definitions [{key, label}]
 * @returns {string} CSV formatted string
 */
function arrayToCsv(data, columns) {
    if (!data || data.length === 0) return '';

    // Header row
    const header = columns.map(col => `"${col.label}"`).join(',');

    // Data rows
    const rows = data.map(item => {
        return columns.map(col => {
            let value = item[col.key];
            if (value === null || value === undefined) value = '';
            if (typeof value === 'object') value = JSON.stringify(value);
            // Escape quotes and wrap in quotes
            return `"${String(value).replace(/"/g, '""')}"`;
        }).join(',');
    });

    return header + '\n' + rows.join('\n');
}

/**
 * Export maturity data (categories and subcategories).
 * @param {string} format - 'csv' or 'json'
 */
function exportMaturityData(format) {
    if (!currentData.maturity) {
        alert('No maturity data available to export.');
        return;
    }

    const timestamp = new Date().toISOString().slice(0, 10);

    if (format === 'json') {
        const exportData = {
            exported_at: new Date().toISOString(),
            overall: currentData.maturity.overall,
            by_category: currentData.maturity.by_category,
            by_subcategory: currentData.maturity.by_subcategory,
            statistics: currentData.maturity.statistics
        };
        downloadFile(
            JSON.stringify(exportData, null, 2),
            `nisify-maturity-${timestamp}.json`,
            'application/json'
        );
    } else {
        // CSV export - flatten subcategories
        const subcategories = Object.entries(currentData.maturity.by_subcategory).map(([id, data]) => ({
            control_id: id,
            function_id: id.split('.')[0],
            category_id: id.split('.').slice(0, 2).join('.'),
            score: data.score,
            level: data.level,
            evidence_count: data.evidence_count || 0,
            confidence: data.confidence || 0
        }));

        const columns = [
            { key: 'control_id', label: 'Control ID' },
            { key: 'function_id', label: 'Function' },
            { key: 'category_id', label: 'Category' },
            { key: 'score', label: 'Score' },
            { key: 'level', label: 'Level' },
            { key: 'evidence_count', label: 'Evidence Count' },
            { key: 'confidence', label: 'Confidence' }
        ];

        downloadFile(
            arrayToCsv(subcategories, columns),
            `nisify-maturity-${timestamp}.csv`,
            'text/csv'
        );
    }
}

/**
 * Export gaps data.
 * @param {string} format - 'csv' or 'json'
 */
function exportGapsData(format) {
    if (!currentData.gaps || !currentData.gaps.all_gaps) {
        alert('No gaps data available to export.');
        return;
    }

    const timestamp = new Date().toISOString().slice(0, 10);

    if (format === 'json') {
        const exportData = {
            exported_at: new Date().toISOString(),
            summary: {
                total_gaps: currentData.gaps.controls_with_gaps,
                gaps_by_priority: currentData.gaps.gaps_by_priority
            },
            gaps: currentData.gaps.all_gaps,
            quick_wins: currentData.gaps.quick_wins,
            recommendations: currentData.gaps.top_recommendations
        };
        downloadFile(
            JSON.stringify(exportData, null, 2),
            `nisify-gaps-${timestamp}.json`,
            'application/json'
        );
    } else {
        const gaps = currentData.gaps.all_gaps.map(gap => ({
            control_id: gap.control_id,
            control_name: gap.control_name || '',
            function_id: gap.function_id,
            category_id: gap.category_id,
            priority: gap.priority,
            gap_type: gap.gap_type,
            current_maturity: gap.current_maturity,
            target_maturity: gap.target_maturity,
            explanation: gap.explanation || ''
        }));

        const columns = [
            { key: 'control_id', label: 'Control ID' },
            { key: 'control_name', label: 'Control Name' },
            { key: 'function_id', label: 'Function' },
            { key: 'category_id', label: 'Category' },
            { key: 'priority', label: 'Priority' },
            { key: 'gap_type', label: 'Gap Type' },
            { key: 'current_maturity', label: 'Current Level' },
            { key: 'target_maturity', label: 'Target Level' },
            { key: 'explanation', label: 'Explanation' }
        ];

        downloadFile(
            arrayToCsv(gaps, columns),
            `nisify-gaps-${timestamp}.csv`,
            'text/csv'
        );
    }
}

/**
 * Export evidence data.
 * @param {string} format - 'csv' or 'json'
 */
function exportEvidenceData(format) {
    if (!currentData.evidence || !currentData.evidence.evidence) {
        alert('No evidence data available to export.');
        return;
    }

    const timestamp = new Date().toISOString().slice(0, 10);

    if (format === 'json') {
        const exportData = {
            exported_at: new Date().toISOString(),
            total: currentData.evidence.total,
            filters: currentData.evidence.filters,
            evidence: currentData.evidence.evidence
        };
        downloadFile(
            JSON.stringify(exportData, null, 2),
            `nisify-evidence-${timestamp}.json`,
            'application/json'
        );
    } else {
        const evidence = currentData.evidence.evidence.map(ev => ({
            id: ev.id,
            platform: ev.platform,
            evidence_type: ev.evidence_type,
            collected_at: ev.collected_at,
            file_hash: ev.file_hash
        }));

        const columns = [
            { key: 'id', label: 'ID' },
            { key: 'platform', label: 'Platform' },
            { key: 'evidence_type', label: 'Evidence Type' },
            { key: 'collected_at', label: 'Collected At' },
            { key: 'file_hash', label: 'File Hash' }
        ];

        downloadFile(
            arrayToCsv(evidence, columns),
            `nisify-evidence-${timestamp}.csv`,
            'text/csv'
        );
    }
}

/**
 * Export trends data.
 * @param {string} format - 'csv' or 'json'
 */
function exportTrendsData(format) {
    if (!currentData.trends) {
        alert('No trends data available to export.');
        return;
    }

    const timestamp = new Date().toISOString().slice(0, 10);

    if (format === 'json') {
        const exportData = {
            exported_at: new Date().toISOString(),
            overall_trend: currentData.trends.overall_trend,
            function_trends: currentData.trends.function_trends,
            improving_controls: currentData.trends.improving_controls,
            regressing_controls: currentData.trends.regressing_controls,
            statistics: currentData.trends.statistics
        };
        downloadFile(
            JSON.stringify(exportData, null, 2),
            `nisify-trends-${timestamp}.json`,
            'application/json'
        );
    } else {
        // Export control trends as CSV
        const allControls = [
            ...(currentData.trends.improving_controls || []).map(c => ({ ...c, status: 'improving' })),
            ...(currentData.trends.stable_controls || []).map(c => ({ ...c, status: 'stable' })),
            ...(currentData.trends.regressing_controls || []).map(c => ({ ...c, status: 'regressing' })),
            ...(currentData.trends.volatile_controls || []).map(c => ({ ...c, status: 'volatile' }))
        ];

        const columns = [
            { key: 'entity_id', label: 'Control ID' },
            { key: 'status', label: 'Trend Status' },
            { key: 'current_score', label: 'Current Score' },
            { key: 'score_delta', label: 'Score Change' },
            { key: 'direction', label: 'Direction' }
        ];

        downloadFile(
            arrayToCsv(allControls, columns),
            `nisify-trends-${timestamp}.csv`,
            'text/csv'
        );
    }
}

// ============================================================================
// Control Detail Modal
// ============================================================================

/**
 * Show control detail modal with evidence.
 * @param {string} controlId - NIST control ID (e.g., "PR.AC-01")
 */
async function showControlDetail(controlId) {
    const modal = document.getElementById('control-modal');
    const title = document.getElementById('control-modal-title');
    const body = document.getElementById('control-modal-body');

    if (!modal || !body) return;

    // Show modal with loading state
    title.textContent = controlId;
    body.innerHTML = '<div class="control-loading">Loading control details...</div>';
    modal.style.display = 'flex';

    try {
        const response = await fetch(`/api/control?id=${encodeURIComponent(controlId)}`);
        const data = await response.json();

        if (data.error) {
            body.innerHTML = `<div class="error-message">${escapeHtml(data.error)}</div>`;
            return;
        }

        renderControlDetail(data, body);
    } catch (error) {
        body.innerHTML = `<div class="error-message">Failed to load control details: ${escapeHtml(error.message)}</div>`;
    }
}

/**
 * Render control detail content in the modal body.
 */
function renderControlDetail(control, container) {
    const levelClass = getLevelClass(control.maturity?.level || 0);

    let html = `
        <div class="control-detail">
            <div class="control-header-info">
                <div class="control-meta">
                    <span class="control-function">${escapeHtml(control.function_id)}</span>
                    <span class="control-category">${escapeHtml(control.category_id)}</span>
                    ${control.api_collectible ? '<span class="badge badge-auto">Auto-collectible</span>' : '<span class="badge badge-manual">Manual</span>'}
                </div>
                <h4>${escapeHtml(control.name)}</h4>
                <p class="control-description">${escapeHtml(control.description)}</p>
            </div>

            <div class="control-maturity-section">
                <h5>Current Maturity</h5>
                <div class="maturity-display-inline">
                    <span class="level-badge ${levelClass} large">Level ${control.maturity?.level || 0}</span>
                    <span class="score-display">${formatNumber(control.maturity?.score || 0)} / 4.0</span>
                    <span class="confidence-display">${formatNumber((control.maturity?.confidence || 0) * 100, 0)}% confidence</span>
                </div>
            </div>

            <div class="control-criteria-section">
                <h5>Maturity Criteria</h5>
                <div class="criteria-list">
    `;

    // Render maturity criteria with current level highlighted
    const criteria = control.maturity_criteria || {};
    for (let i = 0; i <= 4; i++) {
        const isCurrentLevel = i === (control.maturity?.level || 0);
        const criteriaText = criteria[i.toString()] || `Level ${i} criteria not defined`;
        html += `
            <div class="criteria-item ${isCurrentLevel ? 'current' : ''}">
                <span class="criteria-level">Level ${i}</span>
                <span class="criteria-text">${escapeHtml(criteriaText)}</span>
            </div>
        `;
    }

    html += `
                </div>
            </div>

            <div class="control-evidence-types-section">
                <h5>Expected Evidence Types</h5>
                <div class="evidence-types-list">
    `;

    if (control.evidence_types && control.evidence_types.length > 0) {
        for (const evType of control.evidence_types) {
            html += `<span class="evidence-type-tag">${escapeHtml(evType)}</span>`;
        }
    } else {
        html += '<span class="no-evidence-types">No specific evidence types defined</span>';
    }

    html += `
                </div>
            </div>

            <div class="control-evidence-section">
                <h5>Linked Evidence (${control.evidence?.length || 0} items)</h5>
    `;

    if (control.evidence && control.evidence.length > 0) {
        html += '<div class="evidence-list">';
        for (const ev of control.evidence) {
            html += `
                <div class="evidence-item clickable" onclick="showEvidenceDetail('${escapeHtml(ev.id)}')">
                    <div class="evidence-item-header">
                        <span class="evidence-platform">${escapeHtml(ev.platform)}</span>
                        <span class="evidence-type">${escapeHtml(ev.evidence_type)}</span>
                    </div>
                    <div class="evidence-item-meta">
                        <span class="evidence-date">${formatDate(ev.collected_at)}</span>
                        <span class="evidence-hash">${escapeHtml(ev.file_hash)}</span>
                    </div>
                </div>
            `;
        }
        html += '</div>';
    } else {
        html += '<div class="no-evidence">No evidence linked to this control</div>';
    }

    html += `
            </div>
        </div>
    `;

    container.innerHTML = html;
}

/**
 * Close the control detail modal.
 */
function closeControlModal() {
    const modal = document.getElementById('control-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// ============================================================================
// Evidence Detail Modal
// ============================================================================

/**
 * Show evidence detail modal with raw data.
 * @param {string} evidenceId - Evidence item ID
 */
async function showEvidenceDetail(evidenceId) {
    const modal = document.getElementById('evidence-modal');
    const title = document.getElementById('evidence-modal-title');
    const body = document.getElementById('evidence-modal-body');

    if (!modal || !body) return;

    // Show modal with loading state
    title.textContent = 'Evidence Details';
    body.innerHTML = '<div class="evidence-loading">Loading evidence...</div>';
    modal.style.display = 'flex';

    try {
        const response = await fetch(`/api/evidence/detail?id=${encodeURIComponent(evidenceId)}`);
        const data = await response.json();

        if (data.error) {
            body.innerHTML = `<div class="error-message">${escapeHtml(data.error)}</div>`;
            return;
        }

        renderEvidenceDetail(data, body, title);
    } catch (error) {
        body.innerHTML = `<div class="error-message">Failed to load evidence: ${escapeHtml(error.message)}</div>`;
    }
}

/**
 * Render evidence detail content in the modal body.
 */
function renderEvidenceDetail(evidence, container, titleEl) {
    titleEl.textContent = `${evidence.platform}: ${evidence.evidence_type}`;

    let html = `
        <div class="evidence-detail">
            <div class="evidence-detail-header">
                <div class="evidence-detail-meta">
                    <div class="meta-row">
                        <span class="meta-label">Platform:</span>
                        <span class="meta-value">${escapeHtml(evidence.platform)}</span>
                    </div>
                    <div class="meta-row">
                        <span class="meta-label">Type:</span>
                        <span class="meta-value">${escapeHtml(evidence.evidence_type)}</span>
                    </div>
                    <div class="meta-row">
                        <span class="meta-label">Collected:</span>
                        <span class="meta-value">${formatDate(evidence.collected_at)}</span>
                    </div>
                    <div class="meta-row">
                        <span class="meta-label">Items:</span>
                        <span class="meta-value">${evidence.item_count !== null ? evidence.item_count : 'N/A'}</span>
                    </div>
                    <div class="meta-row">
                        <span class="meta-label">Hash:</span>
                        <span class="meta-value hash">${escapeHtml(evidence.file_hash)}</span>
                    </div>
                </div>
            </div>
    `;

    // Mapped controls section
    if (evidence.mapped_controls && evidence.mapped_controls.length > 0) {
        html += `
            <div class="evidence-controls-section">
                <h5>Mapped to Controls (${evidence.mapped_controls.length})</h5>
                <div class="mapped-controls-list">
        `;
        for (const mapping of evidence.mapped_controls) {
            html += `
                <div class="mapped-control clickable" onclick="closeEvidenceModal(); showControlDetail('${escapeHtml(mapping.control_id)}')">
                    <span class="control-id">${escapeHtml(mapping.control_id)}</span>
                    <span class="mapping-confidence">${formatNumber(mapping.confidence * 100, 0)}% confidence</span>
                </div>
            `;
        }
        html += `
                </div>
            </div>
        `;
    }

    // Raw data section
    html += `
            <div class="evidence-raw-section">
                <h5>Raw Data</h5>
                <div class="raw-data-container">
    `;

    if (evidence.raw_data) {
        html += `<pre class="raw-data-content">${escapeHtml(JSON.stringify(evidence.raw_data, null, 2))}</pre>`;
    } else if (evidence.raw_data_error) {
        html += `<div class="error-message">Could not load raw data: ${escapeHtml(evidence.raw_data_error)}</div>`;
    } else {
        html += '<div class="no-data">Raw data not available</div>';
    }

    html += `
                </div>
            </div>
        </div>
    `;

    container.innerHTML = html;
}

/**
 * Close the evidence detail modal.
 */
function closeEvidenceModal() {
    const modal = document.getElementById('evidence-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// Close modals when clicking outside
document.addEventListener('click', function(e) {
    const controlModal = document.getElementById('control-modal');
    const evidenceModal = document.getElementById('evidence-modal');

    if (e.target === controlModal) {
        closeControlModal();
    }
    if (e.target === evidenceModal) {
        closeEvidenceModal();
    }
});

// Close modals with Escape key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeControlModal();
        closeEvidenceModal();
    }
});
