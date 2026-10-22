# PHP2Shell ModSecurity rules

Static detection-only heuristics for multipart requests and their responses.
All rules use `pass`, with no severity assignments, CRS scoring, or engine overrides. There is a section, about how to turn it into blockign rules. 
Alert tag: `php2shell`. Rule IDs: **88295-88310**.

Requires ModSecurity **2.9.7+** or libModSecurity **3.0.8+** and request-body
inspection. Include [php2shell.conf](php2shell.conf) in the existing ModSecurity
configuration.

## Rules

| IDs | Purpose |
| --- | --- |
| 88295-88296 | Mark declared or parsed multipart requests. |
| 88297 | Detect a multipart declaration without the multipart parser. |
| 88298 | Detect body-parser errors and reported inspection-limit violations. |
| 88299 | Flag at least 1000 parsed query/body arguments. |
| 88300-88301 | Flag and log binary controls in ordinary multipart fields. |
| 88302-88303 | Count parsed text and file parts. |
| 88304 | Flag more than 256 combined parts. |
| 88305 | Flag more than 1024 parsed multipart header entries. |
| 88306 | Flag more than 50 file parts. |
| 88307 | Flag at least 17 consecutive closed bracket segments in a field name. |
| 88308 | Flag field names longer than 256 bytes. |
| 88309-88310 | Flag and log raw controls in any cookie value; also encoded controls or values over 256 header bytes in `PHPSESSID`. |

Binary checks exclude uploaded-file contents and TAB/CR/LF. Cookie controls cover
ASCII `00-1F` and `7F`; encoded-control checks apply to percent encodings. Cookie
attributes are excluded, and length is measured before decoding.

The argument threshold is independent of `SecArgumentsLimit`. Header counts use
parsed entries; bracket complexity is not exact PHP nesting depth. Coverage is
partial and depends on the input available to ModSecurity's parser.

Binary and cookie alerts log flags instead of matched values. Audit/debug logging
may still record the underlying data.

## Blocking

With the engine already `On`, change selected request-alert rules
**88297-88299**, **88301**, and **88304-88308**:

`pass,log,auditlog` → `deny,status:403,log,auditlog`

Edit the action line containing the ID; preserve `chain` and other actions.
Keep helpers **88295**, **88296**, **88300**, **88302**, **88303**, **88309**, and
response rule **88310** as `pass`.


## References

- [PHP: RCE via OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP: RCE via stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
