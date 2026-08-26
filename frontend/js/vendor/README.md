# Vendored frontend libraries

These are committed to the repo instead of loaded from a CDN.

| File | Package | Version | License |
|---|---|---|---|
| `marked.umd.js` | [marked](https://github.com/markedjs/marked) | 18.0.10 | MIT (`marked.LICENSE.txt`) |
| `purify.min.js` | [DOMPurify](https://github.com/cure53/DOMPurify) | 3.4.14 | Apache-2.0 / MPL-2.0 (`dompurify.LICENSE.txt`) |

## Why vendored

1. **Air-gapped networks.** Pentesters routinely work from isolated or
   egress-filtered environments. A CDN script tag makes the app degrade there —
   and DOMPurify degrading is a security failure, not a cosmetic one.
2. **Supply chain.** The previous tags pointed at `cdn.jsdelivr.net/npm/<pkg>/`
   with no version and no SRI, so whatever upstream published most recently ran
   in every user's browser alongside their session token.

Both renderers (`js/views/whiteboard.js`, `js/views/ai-agent.js`) fail closed to
escaped plain text when these files are missing, so a broken deploy loses
formatting rather than sanitisation.

## Updating

```bash
npm install marked@<version> dompurify@<version>   # in a scratch directory
cp node_modules/marked/lib/marked.umd.js      frontend/js/vendor/
cp node_modules/dompurify/dist/purify.min.js  frontend/js/vendor/
```

Then update the version numbers in the table above.
