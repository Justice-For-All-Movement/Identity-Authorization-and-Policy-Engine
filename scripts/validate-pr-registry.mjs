import {readFile} from 'node:fs/promises';
import {parsePrRegistry} from '../registry/pr-contract.mjs';
const body = await readFile(new URL('../registry/prs.json', import.meta.url), 'utf8');
// The registry is a historical record written under the repository's former owner. The repository was transferred;
// the record (including its pull-request URLs) is validated strictly against the name it was written under, and the
// running repository must be that name or its one known successor. Any other repository is rejected.
const recorded = JSON.parse(body).repository;
const SUCCESSORS = {'neophilism/identity-authorization-and-policy-engine': 'justice-for-all-movement/identity-authorization-and-policy-engine'};
const running = process.env.GITHUB_REPOSITORY;
if (running && running.toLowerCase() !== String(recorded).toLowerCase() && SUCCESSORS[String(recorded).toLowerCase()] !== running.toLowerCase())
  throw new Error('PR registry belongs to a different repository: ' + recorded);
const repository = recorded;
const {document} = parsePrRegistry(body, repository);
const retired = JSON.parse(await readFile(new URL('../registry/roadmap.json', import.meta.url), 'utf8'));
if (retired.repository !== repository || retired.deprecated !== true || retired.redirectTo !== 'registry/prs.json' ||
    Object.hasOwn(retired, 'milestones') || Object.hasOwn(retired, 'units') || Object.hasOwn(retired, 'plannedPrCount'))
  throw new Error('Only registry/prs.json may contain the active PR plan');
console.log(`Valid PR registry: ${repository}, ${document.units.length} approved units; runtime acceptance is separate.`);
