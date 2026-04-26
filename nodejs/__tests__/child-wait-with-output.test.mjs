import assert from 'node:assert/strict'
import { test } from 'node:test'

import { StdioConfigJs, createSandbox } from '../index.js'

function withTimeout(promise, milliseconds) {
  let timeout
  return Promise.race([
    promise.finally(() => clearTimeout(timeout)),
    new Promise((_, reject) => {
      timeout = setTimeout(
        () => reject(new Error(`operation timed out after ${milliseconds}ms`)),
        milliseconds,
      )
    }),
  ])
}

test('waitWithOutput drains large stdout and stderr before consuming the child', async () => {
  const sandbox = await createSandbox()

  try {
    const script = `
i=0
while [ "$i" -lt 4000 ]; do
  printf 'stdout-%04d-abcdefghijklmnopqrstuvwxyz0123456789\\n' "$i"
  printf 'stderr-%04d-abcdefghijklmnopqrstuvwxyz0123456789\\n' "$i" >&2
  i=$((i + 1))
done
`

    const command = sandbox.command('/bin/sh')
    command.arg('-c')
    command.arg(script)
    command.stdout(StdioConfigJs.Piped)
    command.stderr(StdioConfigJs.Piped)

    const child = await command.spawn()
    const output = await withTimeout(child.waitWithOutput(), 10_000)

    assert.equal(output.status.success, true)
    assert.match(output.stdout.toString(), /stdout-3999-/)
    assert.match(output.stderr.toString(), /stderr-3999-/)

    await assert.rejects(() => child.wait(), /process already consumed/)
    await assert.rejects(() => child.kill(), /process already consumed/)
    await assert.rejects(() => child.tryWait(), /process already consumed/)
    await assert.rejects(() => child.readStdout(1), /process already consumed/)
    await assert.rejects(() => child.readStderr(1), /process already consumed/)
  } finally {
    await sandbox.dispose()
  }
})
