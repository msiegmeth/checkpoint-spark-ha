# Development

## Layout

```
custom_components/checkpoint_spark/   integration (HACS installs this folder)
  api.py           REST client (login, generate-report, show-commands, logout)
  coordinator.py   DataUpdateCoordinator, one session per poll
  config_flow.py   setup, reauth, options
  sensor.py        entities
  diagnostics.py   redacted diagnostics
  strings.json, translations/{en,de}.json
docs/              documentation, anonymised report sample
examples/          dashboard example
.github/workflows  hassfest + HACS validation, release on tag
```

## Local workflow

Symlink the integration into a test instance instead of copying:

```sh
ln -s /path/to/checkpoint-spark-ha/custom_components/checkpoint_spark \
      /config/custom_components/checkpoint_spark
```

Use a relative link if Home Assistant runs in another container that
mounts the config under a different path.

Python changes need a Home Assistant restart. Download diagnostics to see
the decoded reports of your gateway.

## Releases

1. Bump `version` in `custom_components/checkpoint_spark/manifest.json`
2. Add a **readable** section `## [X.Y.Z] - date` to `CHANGELOG.md`
   (New / Changed / Fixed / Upgrade notes, written for users, not commit logs)
3. Commit, tag `vX.Y.Z`, push the tag

The `release` workflow fails without a CHANGELOG section for the version.
It creates the GitHub release with that section as release notes – this is
the text HACS shows in the update dialog. To rewrite the notes of an
existing release: Actions → Release → *Run workflow* with the tag.

## Rules

- Never call anything on the gateway except `login`, `logout`,
  `generate-report` and `show …` clish commands.
- Never commit credentials, session IDs or unredacted report data.
  `docs/report-sample.json` must stay anonymised (IPs, host names, users).
