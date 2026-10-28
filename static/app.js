'use strict';
const $ = (id) => document.getElementById(id);
const form = $('check-form');
const labels = {observed: 'Найдено', caution: 'Обратить внимание', unknown: 'Не удалось подтвердить', not_connected: 'Не подключено'};
let busy = false;

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function sourceLink(url, label) {
  const link = element('a', '', label);
  try {
    const parsed = new URL(url);
    if (!['https:', 'http:'].includes(parsed.protocol)) return element('span', '', 'Источник недоступен');
    link.href = parsed.href;
  } catch { return element('span', '', 'Некорректный источник'); }
  link.target = '_blank';
  link.rel = 'noopener noreferrer';
  return link;
}

function render(data) {
  $('report-domain').textContent = data.host;
  $('report-heading').textContent = data.headline;
  $('report-summary').textContent = data.summary;
  const assessment = data.assessment;
  $('recommendation').textContent = assessment.recommendation;
  $('coverage').textContent = assessment.coverage;
  for (const [id, items, emptyText] of [
    ['assessment-facts', assessment.facts, 'Сведения о магазине, достаточные для оценки продавца, не получены.'],
    ['assessment-gaps', assessment.gaps, 'Пробелы в данных не отмечены. Это не гарантия безопасности.'],
    ['assessment-signals', assessment.signals, ''],
  ]) {
    const rows = items.map(item => {
      const row = element('li');
      const link = element('a', '', item.text);
      link.href = `#check-${item.check_id}`;
      row.append(link);
      return row;
    });
    if (!rows.length && emptyText) rows.push(element('li', 'empty-fact', emptyText));
    $(id).replaceChildren(...rows);
  }
  $('assessment-signals-card').hidden = !assessment.signals.length;
  const date = new Date(data.checked_at).toLocaleString('ru-RU');
  $('report-meta').textContent = `${date} · ${data.duration_seconds} сек. · Автоматические проверки без ИИ`;
  $('check-count').textContent = `${data.checks.length} пунктов`;
  $('checks').replaceChildren();
  for (const check of data.checks) {
    const card = element('article', 'check');
    card.id = `check-${check.id}`;
    const heading = element('div', 'check-heading');
    heading.append(element('h4', '', check.title), element('span', `badge ${check.status}`, labels[check.status] || check.status));
    card.append(heading, element('p', '', check.summary));
    for (const quote of check.evidence) card.append(element('blockquote', 'evidence', quote));
    if (check.sources.length) {
      const links = element('div', 'source-links');
      check.sources.forEach((url, i) => links.append(sourceLink(url, `Источник ${i + 1} →`)));
      card.append(links);
    }
    $('checks').append(card);
  }
  $('next-steps').replaceChildren(...data.next_steps.map(text => element('li', '', text)));
  $('limitations').textContent = data.limitations;
  $('pages').replaceChildren();
  for (const page of data.pages) {
    const row = element('li');
    row.append(sourceLink(page.url, page.url));
    $('pages').append(row);
  }
  if (!data.pages.length) $('pages').append(element('li', '', 'Ни одна страница магазина не была доступна для анализа.'));
  $('page-count').textContent = `(${data.pages.length})`;
  $('report').hidden = false;
  $('report-heading').focus({preventScroll: true});
  $('report').scrollIntoView({behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth', block: 'start'});
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (busy) return;
  const url = $('store-url').value.trim();
  if (!url) return;
  busy = true;
  $('submit').disabled = true;
  $('submit').textContent = 'Проверяем…';
  $('error').hidden = true;
  $('report').hidden = true;
  $('loading').hidden = false;
  form.setAttribute('aria-busy', 'true');
  $('loading-message').textContent = 'Проверяем страницу магазина и историю домена…';
  const timer = setTimeout(() => { $('loading-message').textContent = 'Ожидаем ответы источников. Некоторые сайты ограничивают автоматический доступ…'; }, 10000);
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), 90000);
  try {
    const response = await fetch('/api/check', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({url}), signal: controller.signal});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Не удалось выполнить проверку.');
    render(data);
  } catch (error) {
    $('error').textContent = error.name === 'AbortError' ? 'Истекло время ожидания. Попробуйте ещё раз или проверьте другой магазин.' : error.message === 'Failed to fetch' ? 'Нет соединения с сервером. Убедитесь, что приложение запущено.' : error.message;
    $('error').hidden = false;
  } finally {
    clearTimeout(timer);
    clearTimeout(deadline);
    $('loading').hidden = true;
    $('submit').disabled = false;
    $('submit').replaceChildren(document.createTextNode('Проверить '), element('span', '', '→'));
    form.removeAttribute('aria-busy');
    busy = false;
  }
});

document.querySelectorAll('[data-site]').forEach(button => button.addEventListener('click', () => {
  if (busy) return;
  $('store-url').value = button.dataset.site;
  form.requestSubmit();
}));
$('print').addEventListener('click', () => window.print());
