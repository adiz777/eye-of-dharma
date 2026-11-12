#!/usr/bin/env node
/**
 * EYE OF DHARMA (EOD) — Standalone E2E Test Suite Runner
 * Executes Tier 1-4 opaque-box verification suites and outputs telemetry.
 */

import { performance } from 'node:perf_hooks';
import { TestCase, TestResult } from './e2e/helpers.js';
import { tier1Tests } from './e2e/tier1_feature.test.js';
import { tier2Tests } from './e2e/tier2_boundary.test.js';
import { tier3Tests } from './e2e/tier3_pairwise.test.js';
import { tier4Tests } from './e2e/tier4_scenarios.test.js';

interface RunnerOptions {
  tier?: number;
  bail?: boolean;
  verbose?: boolean;
  json?: boolean;
}

function parseCliArgs(): RunnerOptions {
  const args = process.argv.slice(2);
  const options: RunnerOptions = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--tier' && i + 1 < args.length) {
      options.tier = parseInt(args[++i], 10);
    } else if (arg === '--bail') {
      options.bail = true;
    } else if (arg === '--verbose') {
      options.verbose = true;
    } else if (arg === '--json') {
      options.json = true;
    }
  }

  return options;
}

async function runTest(test: TestCase, options: RunnerOptions): Promise<TestResult> {
  const start = performance.now();
  try {
    await test.fn();
    const durationMs = Math.round((performance.now() - start) * 100) / 100;
    if (options.verbose && !options.json) {
      console.log(`  [PASS] [Tier ${test.tier}] ${test.name} (${durationMs}ms)`);
    }
    return {
      name: test.name,
      tier: test.tier,
      area: test.area,
      passed: true,
      durationMs
    };
  } catch (err: any) {
    const durationMs = Math.round((performance.now() - start) * 100) / 100;
    const errorMsg = err?.message || String(err);
    if (!options.json) {
      console.error(`  [FAIL] [Tier ${test.tier}] ${test.name} (${durationMs}ms)`);
      console.error(`         Error: ${errorMsg}`);
    }
    return {
      name: test.name,
      tier: test.tier,
      area: test.area,
      passed: false,
      durationMs,
      error: errorMsg
    };
  }
}

async function main() {
  const options = parseCliArgs();

  const allTests: TestCase[] = [
    ...tier1Tests,
    ...tier2Tests,
    ...tier3Tests,
    ...tier4Tests
  ];

  const selectedTests = options.tier
    ? allTests.filter(t => t.tier === options.tier)
    : allTests;

  if (!options.json) {
    console.log('\n================================================================');
    console.log('   EYE OF DHARMA (EOD) // E2E VERIFICATION TEST RUNNER          ');
    console.log('   Integrity Mode: Development | Scope: Tiers 1-4 Verification  ');
    console.log('================================================================');
    console.log(`Execution Plan: ${selectedTests.length} tests selected across ${options.tier ? `Tier ${options.tier}` : 'all Tiers (1-4)'}.\n`);
  }

  const results: TestResult[] = [];
  const suiteStart = performance.now();

  for (const test of selectedTests) {
    const result = await runTest(test, options);
    results.push(result);

    if (options.bail && !result.passed) {
      if (!options.json) {
        console.log('\n[!] Execution halted due to --bail flag.');
      }
      break;
    }
  }

  const totalDuration = Math.round(performance.now() - suiteStart);
  const totalPassed = results.filter(r => r.passed).length;
  const totalFailed = results.filter(r => !r.passed).length;

  // Breakdown by Tier
  const tierBreakdown: Record<number, { total: number; passed: number; failed: number }> = {};
  for (const r of results) {
    if (!tierBreakdown[r.tier]) {
      tierBreakdown[r.tier] = { total: 0, passed: 0, failed: 0 };
    }
    tierBreakdown[r.tier].total++;
    if (r.passed) tierBreakdown[r.tier].passed++;
    else tierBreakdown[r.tier].failed++;
  }

  if (options.json) {
    console.log(
      JSON.stringify(
        {
          timestamp: new Date().toISOString(),
          totalTests: results.length,
          passed: totalPassed,
          failed: totalFailed,
          durationMs: totalDuration,
          tierBreakdown,
          results
        },
        null,
        2
      )
    );
    process.exit(totalFailed > 0 ? 1 : 0);
  }

  console.log('\n----------------------------------------------------------------');
  console.log('                       EXECUTION SUMMARY                        ');
  console.log('----------------------------------------------------------------');

  for (const [tier, stat] of Object.entries(tierBreakdown)) {
    const tierName =
      tier === '1'
        ? 'Tier 1: Feature Coverage      '
        : tier === '2'
        ? 'Tier 2: Boundary & Corner Cases'
        : tier === '3'
        ? 'Tier 3: Pairwise Pipelines    '
        : 'Tier 4: Mission Scenarios     ';
    const status = stat.failed === 0 ? 'PASS' : 'FAIL';
    console.log(` ${tierName} : [${status}] ${stat.passed}/${stat.total} passed`);
  }

  console.log('----------------------------------------------------------------');
  console.log(` TOTAL TESTS : ${results.length}`);
  console.log(` PASSED      : ${totalPassed}`);
  console.log(` FAILED      : ${totalFailed}`);
  console.log(` DURATION    : ${totalDuration}ms`);
  console.log('----------------------------------------------------------------');

  if (totalFailed === 0) {
    console.log(' [✓] ALL E2E VERIFICATION GATES PASSED NOMINAL.\n');
    process.exit(0);
  } else {
    console.error(` [✗] ${totalFailed} TEST(S) FAILED. VERIFICATION REJECTED.\n`);
    process.exit(1);
  }
}

main().catch(err => {
  console.error('Fatal runner exception:', err);
  process.exit(1);
});
