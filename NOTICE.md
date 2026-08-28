# Authorization & use

This lab reproduces Apache Log4j2 issue #4255 (FilteredObjectInputStream
allowlist bypass via `java.rmi.MarshalledObject`) for **defensive security
research and authorized testing only**.

- Run it against your own machine and your own disposable Docker containers.
- The `--oob` self-check is the only command that contacts a host you name — use
  it **only** against systems you own or are explicitly authorized in writing to
  test. Probing third-party systems without authorization is unlawful, benign
  payload or not.
- No warranty. The authors accept no liability for misuse.

Third-party components are **not** included and are fetched/supplied at use time:

- Official Apache Log4j jars and commons-collections — fetched from Maven Central
  at image build time (Apache License 2.0).
- ysoserial — you supply it via `YSOSERIAL=/path/to/ysoserial.jar`
  (https://github.com/frohoff/ysoserial, MIT).

See `README.md` → *Attribution* for credit to prior work.
