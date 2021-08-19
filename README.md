# sherman
Command remote hosts via SSH

`sherman` is named after the American commander General William Tecumseh Sherman. This tool makes bad compromises and bargains, and it
isn't the hero you want or need.

The goal of this tool is to be an extremely minimalist method to run remote commands, upload scripts and execute them on remote systems,
and save the returned data. Remote connections will be pooled by the threading library for concurrency and simultaneous connection limiting.

Most of this already exists in various Bash scripts, but better error handling and pooling without maintaining lists of PIDs in arrays is desirable.
