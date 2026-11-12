// server/connectors/entity_sources.ts
// Lawful public-source lookups for people (public figures), organisations and usernames.
// Deliberately NOT included: people-search/data brokers, scraping of social platforms, anything behind a login.

import { safeFetch } from '../security/ssrf.js';

export type SourceStatus = 'found' | 'not_found' | 'error' | 'unsupported';
export type EntityQueryType = 'PERSON' | 'ORGANIZATION' | 'USERNAME';

export interface EntityRecord {
  label: string;
  url?: string;
  details?: Record<string, unknown>;
}

export interface SourceResult {
  sourceId: string;
  sourceName: string;
  status: SourceStatus;
  records: EntityRecord[];
  note?: string;
  retrievedAt: string;
}

const UA = `EyeOfDharma/0.1 (${process.env.EOD_CONTACT_EMAIL || 'set EOD_CONTACT_EMAIL'})`;

async function getJson(url: string, headers: Record<string, string> = {}): Promise<{ status: number; json: any }> {
  const res = await safeFetch(url, { timeoutMs: 8000, maxBytes: 3 * 1024 * 1024, headers: { Accept: 'application/json', 'User-Agent': UA, ...headers } });
  let json: any = null;
  try { json = JSON.parse(res.data); } catch { /* non-JSON body: leave null */ }
  return { status: res.statusCode, json };
}

async function run(
  sourceId: string,
  sourceName: string,
  fn: () => Promise<{ records: EntityRecord[]; note?: string } | 'unsupported'>,
  unsupportedNote?: string
): Promise<SourceResult> {
  const retrievedAt = new Date().toISOString();
  try {
    const out = await fn();
    if (out === 'unsupported') return { sourceId, sourceName, status: 'unsupported', records: [], note: unsupportedNote, retrievedAt };
    return { sourceId, sourceName, status: out.records.length ? 'found' : 'not_found', records: out.records, note: out.note, retrievedAt };
  } catch (err) {
    return { sourceId, sourceName, status: 'error', records: [], note: err instanceof Error ? err.message : String(err), retrievedAt };
  }
}

export const lookupWikidata = (q: string) =>
  run('wikidata', 'Wikidata (public figures & organisations)', async () => {
    const { status, json } = await getJson(`https://www.wikidata.org/w/api.php?action=wbsearchentities&search=${encodeURIComponent(q)}&language=en&format=json&limit=5`);
    if (status !== 200 || !json) throw new Error(`HTTP ${status}`);
    return { records: (json.search || []).map((s: any) => ({ label: s.label, url: s.concepturi, details: { id: s.id, description: s.description } })) };
  });

export const lookupGleif = (q: string) =>
  run('gleif', 'GLEIF Legal Entity Identifiers', async () => {
    const { status, json } = await getJson(`https://api.gleif.org/api/v1/fuzzycompletions?field=entity.legalName&q=${encodeURIComponent(q)}`);
    if (status !== 200 || !json) throw new Error(`HTTP ${status}`);
    return {
      records: (json.data || []).slice(0, 5).map((d: any) => {
        const lei = d.relationships?.['lei-records']?.data?.id;
        return { label: d.attributes?.value, url: lei ? `https://search.gleif.org/#/record/${lei}` : undefined, details: { lei } };
      })
    };
  });

let tickerCache: { at: number; rows: any[] } | null = null;
export const lookupSec = (q: string) =>
  run('sec_edgar', 'US SEC EDGAR (listed companies)', async () => {
    if (!process.env.EOD_CONTACT_EMAIL) return 'unsupported';
    if (!tickerCache || Date.now() - tickerCache.at > 24 * 3600 * 1000) {
      const { status, json } = await getJson('https://www.sec.gov/files/company_tickers.json');
      if (status !== 200 || !json) throw new Error(`HTTP ${status}`);
      tickerCache = { at: Date.now(), rows: Object.values(json) };
    }
    const needle = q.toLowerCase();
    return {
      records: tickerCache.rows
        .filter((r: any) => String(r.title).toLowerCase().includes(needle))
        .slice(0, 5)
        .map((r: any) => ({ label: r.title, url: `https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=${r.cik_str}`, details: { cik: r.cik_str, ticker: r.ticker } }))
    };
  }, 'Requires a contact email for the SEC User-Agent policy: set EOD_CONTACT_EMAIL');

export const lookupCompaniesHouse = (q: string) => {
  const key = process.env.COMPANIES_HOUSE_API_KEY;
  return run('companies_house', 'UK Companies House', async () => {
    if (!key) return 'unsupported';
    const auth = 'Basic ' + Buffer.from(`${key}:`).toString('base64');
    const { status, json } = await getJson(`https://api.company-information.service.gov.uk/search/companies?q=${encodeURIComponent(q)}&items_per_page=5`, { Authorization: auth });
    if (status !== 200 || !json) throw new Error(`HTTP ${status}`);
    return {
      records: (json.items || []).map((c: any) => ({
        label: c.title,
        url: `https://find-and-update.company-information.service.gov.uk/company/${c.company_number}`,
        details: { number: c.company_number, status: c.company_status, created: c.date_of_creation }
      }))
    };
  }, 'Requires a free API key: set COMPANIES_HOUSE_API_KEY');
};

export const lookupOpenSanctions = (q: string) => {
  const key = process.env.OPENSANCTIONS_API_KEY;
  return run('opensanctions', 'OpenSanctions (sanctions / PEP lists)', async () => {
    if (!key) return 'unsupported';
    const { status, json } = await getJson(`https://api.opensanctions.org/search/default?q=${encodeURIComponent(q)}&limit=5`, { Authorization: `ApiKey ${key}` });
    if (status !== 200 || !json) throw new Error(`HTTP ${status}`);
    return {
      records: (json.results || []).map((r: any) => ({
        label: r.caption,
        url: `https://www.opensanctions.org/entities/${r.id}/`,
        details: { schema: r.schema, datasets: r.datasets, note: 'A name match is a lead, not an identity match.' }
      }))
    };
  }, 'Requires an API key (free for non-commercial use): set OPENSANCTIONS_API_KEY');
};

const USERNAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,38}$/;

export const lookupGithubUser = (u: string) =>
  run('github', 'GitHub public profile', async () => {
    const { status, json } = await getJson(`https://api.github.com/users/${encodeURIComponent(u)}`);
    if (status === 404) return { records: [] };
    if (status !== 200 || !json) throw new Error(`HTTP ${status}`);
    return { records: [{ label: json.login, url: json.html_url, details: { type: json.type, created_at: json.created_at, public_repos: json.public_repos } }] };
  });

export const lookupGitlabUser = (u: string) =>
  run('gitlab', 'GitLab public profile', async () => {
    const { status, json } = await getJson(`https://gitlab.com/api/v4/users?username=${encodeURIComponent(u)}`);
    if (status !== 200 || !Array.isArray(json)) throw new Error(`HTTP ${status}`);
    return { records: json.map((x: any) => ({ label: x.username, url: x.web_url, details: { state: x.state } })) };
  });

export const lookupHackerNews = (u: string) =>
  run('hackernews', 'Hacker News public profile', async () => {
    const { status, json } = await getJson(`https://hacker-news.firebaseio.com/v0/user/${encodeURIComponent(u)}.json`);
    if (status !== 200) throw new Error(`HTTP ${status}`);
    return { records: json ? [{ label: json.id, url: `https://news.ycombinator.com/user?id=${encodeURIComponent(json.id)}`, details: { created: json.created, karma: json.karma } }] : [] };
  });

/** Which sources run for each query type. Persons are limited to public-figure / sanctions-list sources by design. */
export async function runEntityLookup(type: EntityQueryType, target: string): Promise<SourceResult[]> {
  if (type === 'USERNAME') {
    if (!USERNAME_RE.test(target)) throw new Error('Username must be 1-39 chars: letters, digits, _ . -');
    return Promise.all([lookupGithubUser(target), lookupGitlabUser(target), lookupHackerNews(target)]);
  }
  if (type === 'PERSON') return Promise.all([lookupWikidata(target), lookupOpenSanctions(target)]);
  return Promise.all([lookupWikidata(target), lookupGleif(target), lookupSec(target), lookupCompaniesHouse(target), lookupOpenSanctions(target)]);
}
