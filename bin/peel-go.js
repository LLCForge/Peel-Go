#!/usr/bin/env node
// Peel-Go komut satırı. Kullanım: peel-go <dosya|dizin|-> [-o çıktı] [-f biçim] [-d dizin] [-r json|text|rapor.json] (peel-go --help)
import { runCli, EXIT } from '../src/cli/run.js';
import { UsageError } from '../src/cli/args.js';

// çıktı bir boruya (ör. | head) verilip erken kapanırsa sessizce çık
process.stdout.on('error', (e) => { if (e.code === 'EPIPE') process.exit(process.exitCode ?? 0); throw e; });

try {
  process.exitCode = await runCli(process.argv.slice(2));
} catch (e) {
  if (e instanceof UsageError) {
    console.error(e.message);
    process.exitCode = EXIT.USAGE;
  } else {
    console.error(`Hata: ${e.message}`);
    process.exitCode = EXIT.ERROR;
  }
}
