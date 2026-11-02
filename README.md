# instagram-skill-importer

Claude Code skill that reads one saved Instagram collection, lists the Claude skills mentioned in its posts, reviews their source repositories statically, and installs only the skills you approve into a local skill vault.

- Reads through your logged-in Chrome session with Claude in Chrome. It never handles passwords or interacts with posts.
- Automated viewing may conflict with Instagram's terms or trigger account limits. It reads one collection slowly and stops on any challenge screen.
- A static review cannot prove that a skill is safe. Read the report before approving.

## Tests

    python3 -m unittest discover -s tests -p 'test_*.py'
