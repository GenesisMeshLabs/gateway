// The guided tour verifies evidence in the browser. Check it against records
// signed by the Python reference (tests/reference/python-evidence-vectors.json,
// shared with the SDKs): the whole export verifies, tampering is caught, and
// floats re-serialize as Python writes them.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';

const source = readFileSync(new URL('../ui/tour.js', import.meta.url), 'utf8');
const {canonical, checkEvents, parsePreserving, pythonFloat} =
  await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
const v = JSON.parse(readFileSync(new URL('../tests/reference/python-evidence-vectors.json', import.meta.url), 'utf8'));

const python = text => execFileSync('python', ['-X', 'utf8', '-c',
  'import sys,json; print(json.dumps(json.loads(sys.stdin.read()),sort_keys=True,separators=(",",":")))'],
  {input: text, encoding: 'utf8'}).trim();
for (const text of ['{"a":1.0,"b":-0.0,"c":1e-7,"d":12345678901234567890,"e":0.1,"f":1e16,"g":123.456,"h":"Zoë 😀"}',
                    '[90.0, 1e-05, 0.0001, 2.5e+20, 9007199254740993]']) {
  assert.equal(canonical(parsePreserving(text)), python(text), text);
}
assert.equal(pythonFloat(1e-7), '1e-07');

const lines = v.export.split('\n').filter(l => l.trim());
const events = lines.map(parsePreserving);
const result = await checkEvents(events, v.na_public_key, v.executor_keys, v.resource_id);
assert.deepEqual(result.failures, []);
assert.equal(result.decisions, v.server_verification.decisions);
assert.equal(result.executions, v.server_verification.executions);
assert.equal(result.last.digest, v.execution_digests[v.execution_digests.length - 1]);

const tampered = lines.map(parsePreserving);
const execution = tampered.find(e => e.entry.entry_kind === 'execution');
execution.payload.outcome = 'failure';
const caught = await checkEvents(tampered, v.na_public_key, v.executor_keys, v.resource_id);
assert(caught.failures.some(f => f.endsWith('payload digest')), caught.failures.join());
assert(caught.failures.some(f => f.endsWith('execution signature')), caught.failures.join());
const wrongKey = await checkEvents(lines.map(parsePreserving), v.executor_keys[0].public_key, v.executor_keys, v.resource_id);
assert(wrongKey.failures.some(f => f.endsWith('decision signature')));
console.log('Tour evidence verification matches the Python reference; tampering and wrong keys are caught.');
