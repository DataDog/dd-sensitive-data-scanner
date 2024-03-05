# SDS Fuzz Tester

This uses AFL (American Fuzzy Lop) to generate input that will try to make the test program fail (panic / crash /
freeze / etc.).

The test program (`main.rs`) will take the input, convert it into a regex pattern / input and then run some, run the
scanner, then run sanity checks / asserts on the result.

By default, the `hyperscan` feature of the fuzz tester is enabled, which allowing comparing the results against
Hyperscan. To run the fuzz tester without this (on architectures that don't support Hyperscan) disable the feature
with `--no-default-features`

## How to run

- Install AFL (`cargo install cargo-afl`).
- You may need to run `cargo-afl afl system-config` (You will get an error when running if this is needed)
- Add any additional starting inputs as desired to `inputs.txt`. These should all be VALID inputs. This helps AFL find "
  interesting" inputs faster. Each line is treated as a separate input. Do not modify files in the `in/` directory,
  those are generated automatically.
- Run the fuzzer with `./run_fuzz.sh`. This will run forever. Just let it run for as long as you are willing (it could
  take hours or days to find a crash).
- For an explanation of what the status screen means, you can read more about it
  here: https://lcamtuf.coredump.cx/afl/status_screen.txt
- the `out` directory will be populated with any issues found. The `crashes` or `hangs` directory inside here will
  contain files of the input used to cause the failure.
- If any crashes are unique / currently unknown, open a Jira issue for the issue.

## Troubleshooting / Known issues

- If you get an error about "on-demand CPU frequency scaling" and don't want to follow the instructions to fix it, you
  can just set the `AFL_SKIP_CPUFREQ` environment variable to `true` to skip this step. Fuzzing will be a bit slower.
- The scripts provided only run AFL on a single core. This can be improved in the future to utilize more cores.