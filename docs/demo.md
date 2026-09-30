# SPAF Demo

A short tour of the SPAF CLI. The commands below are safe to run offline
(`--no-db --no-ai`) against `example.com`.

## Quick tour

```bash
spaf tools                      # what's installed
spaf tools --install            # install the Go recon suite (needs Go)
spaf scope add example.com      # define engagement scope
spaf toolkit example.com        # subfinder → httpx → katana → nuclei
spaf recon example.com --passive
spaf report example.com --format html --with-ai   # shareable HTML report
```

## Recording the GIF for the README

The README references `docs/demo.gif`. To (re)generate it:

```bash
pip install asciinema
# install agg (asciinema -> gif): https://github.com/asciinema/agg

asciinema rec docs/demo.cast -c "bash scripts/demo.sh"
agg docs/demo.cast docs/demo.gif
```

Then commit `docs/demo.gif`. Keep it short (~15–20s) and run it after
`spaf tools --install` so the toolkit stages show real output.
