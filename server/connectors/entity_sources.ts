// server/connectors/entity_sources.ts
// Lawful public-source lookups for people (public figures), organisations and usernames.
// Deliberately NOT included: people-search/data brokers, scraping of social platforms, anything behind a login.

import { safeFetch } from '../security/ssrf.js';

export type SourceStatus = 'found' | 'not_found' | 'error' | 'unsupported';
export type EntityQueryType = 'PERSON' | 'ORGANIZATION' | 'USERNAME' | 'COMPANY_NETWORK';

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

async function getJson(url: string, headers: Record<string, string> = {}, timeoutMs = 8000): Promise<{ status: number; json: any }> {
  const res = await safeFetch(url, { timeoutMs, maxBytes: 3 * 1024 * 1024, headers: { Accept: 'application/json', 'User-Agent': UA, ...headers } });
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

const WIKIDATA_PERSON_PROPS: Array<[string, string]> = [
  ['P169', 'CEO'],
  ['P112', 'founder'],
  ['P488', 'chairperson'],
  ['P3320', 'board member'],
  ['P1037', 'director / manager']
];

/** People publicly tied to a company in Wikidata via wbgetentities claims (avoids slow SPARQL timeouts). */
export const lookupWikidataPeople = (company: string) =>
  run('wikidata_people', 'Wikidata: documented people linked to the company', async () => {
    const s = await getJson(`https://www.wikidata.org/w/api.php?action=wbsearchentities&search=${encodeURIComponent(company)}&language=en&format=json&limit=1`);
    const qid: string | undefined = s.json?.search?.[0]?.id;
    if (!qid || !/^Q\d+$/.test(qid)) return { records: [] };
    const ent = await getJson(`https://www.wikidata.org/w/api.php?action=wbgetentities&ids=${qid}&props=claims&format=json`);
    if (ent.status !== 200 || !ent.json?.entities?.[qid]) throw new Error(`HTTP ${ent.status}`);
    const claims = ent.json.entities[qid].claims || {};
    const links: Array<{ pid: string; relation: string }> = [];
    const seen = new Set<string>();
    for (const [prop, rel] of WIKIDATA_PERSON_PROPS) {
      for (const c of claims[prop] || []) {
        const pid: string | undefined = c?.mainsnak?.datavalue?.value?.id;
        if (pid && /^Q\d+$/.test(pid) && !seen.has(`${pid}:${rel}`)) {
          seen.add(`${pid}:${rel}`);
          links.push({ pid, relation: rel });
        }
      }
    }
    if (!links.length) return { note: `Matched company entity ${qid}; no CEO/founder/board claims found.`, records: [] };
    const uniquePids = Array.from(new Set(links.map((l) => l.pid))).slice(0, 30);
    const meta = await getJson(`https://www.wikidata.org/w/api.php?action=wbgetentities&ids=${uniquePids.join('|')}&props=labels|descriptions&languages=en&format=json`);
    const entities = meta.json?.entities || {};
    return {
      note: `Matched company entity ${qid} (first search hit: verify it is the right one).`,
      records: links.slice(0, 30).map(({ pid, relation }) => ({
        label: entities[pid]?.labels?.en?.value || pid,
        url: `https://www.wikidata.org/wiki/${pid}`,
        details: { relation, description: entities[pid]?.descriptions?.en?.value, company: qid }
      }))
    };
  });

/** Officers (directors/secretaries) from the UK statutory register. DOB/address deliberately not returned. */
export const lookupCompaniesHouseOfficers = (company: string) => {
  const key = process.env.COMPANIES_HOUSE_API_KEY;
  return run('companies_house_officers', 'UK Companies House: registered officers', async () => {
    if (!key) return 'unsupported';
    const auth = 'Basic ' + Buffer.from(`${key}:`).toString('base64');
    const s = await getJson(`https://api.company-information.service.gov.uk/search/companies?q=${encodeURIComponent(company)}&items_per_page=1`, { Authorization: auth });
    const num = s.json?.items?.[0]?.company_number;
    if (!num) return { records: [] };
    const { status, json } = await getJson(`https://api.company-information.service.gov.uk/company/${encodeURIComponent(num)}/officers?items_per_page=20`, { Authorization: auth });
    if (status !== 200 || !json) throw new Error(`HTTP ${status}`);
    return {
      note: `Company ${s.json.items[0].title} (${num}), first search hit: verify.`,
      records: (json.items || []).map((o: any) => ({
        label: o.name,
        url: `https://find-and-update.company-information.service.gov.uk/company/${num}/officers`,
        details: { role: o.officer_role, appointed_on: o.appointed_on, resigned_on: o.resigned_on }
      }))
    };
  }, 'Requires a free API key: set COMPANIES_HOUSE_API_KEY');
};

export const lookupKeybaseUser = (u: string) =>
  run('keybase', 'Keybase public profile & identity proofs', async () => {
    const { status, json } = await getJson(`https://keybase.io/_/api/1.0/user/lookup.json?usernames=${encodeURIComponent(u)}&fields=basics,profile,proofs_summary`);
    if (status !== 200 || !json) throw new Error(`HTTP ${status}`);
    const user = (json.them || [])[0];
    if (!user?.basics?.username) return { records: [] };
    const proofs = (user.proofs_summary?.all || []).map((p: any) => `${p.proof_type}:${p.nametag}`);
    return {
      records: [{
        label: user.profile?.full_name ? `${user.basics.username} (${user.profile.full_name})` : user.basics.username,
        url: `https://keybase.io/${encodeURIComponent(user.basics.username)}`,
        details: { location: user.profile?.location, proofs }
      }]
    };
  });

export const lookupBlueskyUser = (u: string) =>
  run('bluesky', 'Bluesky public profile', async () => {
    const actor = u.includes('.') ? u : `${u}.bsky.social`;
    const { status, json } = await getJson(`https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=${encodeURIComponent(actor)}`);
    if (status === 400 || status === 404) return { records: [] };
    if (status !== 200 || !json?.handle) throw new Error(`HTTP ${status}`);
    return {
      records: [{
        label: json.displayName ? `${json.handle} (${json.displayName})` : json.handle,
        url: `https://bsky.app/profile/${encodeURIComponent(json.handle)}`,
        details: { followers: json.followersCount, posts: json.postsCount, description: json.description }
      }]
    };
  });

export const lookupMastodonUser = (u: string) =>
  run('mastodon', 'Mastodon (mastodon.social) public profile', async () => {
    const { status, json } = await getJson(`https://mastodon.social/api/v1/accounts/lookup?acct=${encodeURIComponent(u)}`);
    if (status === 404) return { records: [] };
    if (status !== 200 || !json?.acct) throw new Error(`HTTP ${status}`);
    return {
      records: [{
        label: json.display_name ? `@${json.acct} (${json.display_name})` : `@${json.acct}`,
        url: json.url,
        details: { followers: json.followers_count, statuses: json.statuses_count, created_at: json.created_at }
      }]
    };
  });

export const lookupDevToUser = (u: string) =>
  run('devto', 'Dev.to public profile', async () => {
    const { status, json } = await getJson(`https://dev.to/api/users/by_username?url=${encodeURIComponent(u)}`);
    if (status === 404) return { records: [] };
    if (status !== 200 || !json?.username) throw new Error(`HTTP ${status}`);
    return {
      records: [{
        label: json.name ? `${json.username} (${json.name})` : json.username,
        url: `https://dev.to/${encodeURIComponent(json.username)}`,
        details: { location: json.location, joined_at: json.joined_at }
      }]
    };
  });

export const lookupStackOverflowUser = (u: string) =>
  run('stackoverflow', 'Stack Overflow public profile', async () => {
    const { status, json } = await getJson(`https://api.stackexchange.com/2.3/users?inname=${encodeURIComponent(u)}&site=stackoverflow&pagesize=3&sort=reputation&order=desc`);
    if (status !== 200 || !json) throw new Error(`HTTP ${status}`);
    const needle = u.toLowerCase();
    const exact = (json.items || []).filter((x: any) => String(x.display_name || '').toLowerCase() === needle);
    return {
      records: exact.map((x: any) => ({
        label: x.display_name,
        url: x.link,
        details: { reputation: x.reputation, location: x.location }
      }))
    };
  });

export const lookupOpenAlexAuthor = (q: string) =>
  run('openalex_author', 'OpenAlex academic publications & affiliations', async () => {
    const { status, json } = await getJson(`https://api.openalex.org/authors?search=${encodeURIComponent(q)}&per-page=5`);
    if (status !== 200 || !json) throw new Error(`HTTP ${status}`);
    return {
      records: (json.results || []).slice(0, 5).map((a: any) => ({
        label: a.display_name,
        url: a.id ? `https://openalex.org/authors/${String(a.id).split('/').pop()}` : undefined,
        details: {
          works_count: a.works_count,
          cited_by_count: a.cited_by_count,
          h_index: a.summary_stats?.h_index,
          orcid: a.orcid,
          institutions: (a.last_known_institutions || []).map((i: any) => i.display_name).filter(Boolean).slice(0, 3)
        }
      }))
    };
  });

export const lookupOrcid = (q: string) =>
  run('orcid', 'ORCID researcher registry', async () => {
    const { status, json } = await getJson(`https://pub.orcid.org/v3.0/expanded-search/?q=${encodeURIComponent(q)}&rows=5`);
    if (status !== 200 || !json) throw new Error(`HTTP ${status}`);
    return {
      records: (json['expanded-result'] || []).slice(0, 5).map((h: any) => {
        const name = [h['given-names'], h['family-names']].filter(Boolean).join(' ') || h['orcid-id'];
        return {
          label: name,
          url: `https://orcid.org/${encodeURIComponent(h['orcid-id'])}`,
          details: { orcid: h['orcid-id'], institutions: (h['institution-name'] || []).slice(0, 3) }
        };
      })
    };
  });

export const lookupOpenAlexInstitution = (company: string) =>
  run('openalex_institution', 'OpenAlex research institutions & R&D output', async () => {
    const { status, json } = await getJson(`https://api.openalex.org/institutions?search=${encodeURIComponent(company)}&per-page=3`);
    if (status !== 200 || !json) throw new Error(`HTTP ${status}`);
    return {
      records: (json.results || []).slice(0, 3).map((i: any) => ({
        label: i.display_name,
        url: i.id ? `https://openalex.org/institutions/${String(i.id).split('/').pop()}` : undefined,
        details: { country: i.country_code, type: i.type, works_count: i.works_count, ror: i.ror }
      }))
    };
  });

/** Recent news articles mentioning the company (GDELT, public index; links only, no content copied). */
export const lookupGdeltNews = (company: string) =>
  run('gdelt', 'GDELT news mentions', async () => {
    const url = `https://api.gdeltproject.org/api/v2/doc/doc?query=${encodeURIComponent(`"${company}"`)}&mode=artlist&format=json&maxrecords=10&sort=datedesc`;
    let r = await getJson(url);
    if (r.status === 429) { await new Promise((res) => setTimeout(res, 5500)); r = await getJson(url); }
    const { status, json } = r;
    if (status === 429) throw new Error('HTTP 429 (GDELT rate-limits to ~1 request / 5s; retry shortly)');
    if (status !== 200 || !json) throw new Error(`HTTP ${status}`);
    return { records: (json.articles || []).map((a: any) => ({ label: a.title, url: a.url, details: { domain: a.domain, seen: a.seendate, country: a.sourcecountry } })) };
  });
/** Which sources run for each query type. Persons are limited to public-figure / sanctions-list sources by design. */
export async function runEntityLookup(type: EntityQueryType, target: string): Promise<SourceResult[]> {
  if (type === 'USERNAME') {
    if (!USERNAME_RE.test(target)) throw new Error('Username must be 1-39 chars: letters, digits, _ . -');
    return Promise.all([lookupGithubUser(target), lookupGitlabUser(target), lookupHackerNews(target), lookupKeybaseUser(target), lookupBlueskyUser(target), lookupMastodonUser(target), lookupDevToUser(target), lookupStackOverflowUser(target)]);
  }
  if (type === 'COMPANY_NETWORK') return Promise.all([lookupWikidataPeople(target), lookupCompaniesHouseOfficers(target), lookupGdeltNews(target), lookupOpenAlexInstitution(target)]);
  if (type === 'PERSON') return Promise.all([lookupWikidata(target), lookupOpenAlexAuthor(target), lookupOrcid(target), lookupOpenSanctions(target)]);
  return Promise.all([lookupWikidata(target), lookupGleif(target), lookupSec(target), lookupCompaniesHouse(target), lookupOpenSanctions(target)]);
}
