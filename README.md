# Wazoo 

This project is a wazuh server **4.X** that can handle wazuh agent connection.

## What is Wazoo

Wazoo is a wazuh server that can handle wazuh agent connection and logging.

**wazoo does not replace wazuh** but you can use to send logs to other platforms or make new integrations with wazuh.

I made wazoo to study the wazuh agent enrolment and I ended up getting excited and doing this project.

With this project you can receive logs from wazuh agent and logging into a **TCP, UDP, Unix, TCP+SSL or File**

# Installation & Configuration

You can run this project using: *docker*, *uv* or *pre-compiled binaries*



## Performance

This python wazuh server, is not performant than wazuh server but can 

- **asyncio** ( for async connection )
- **uvloop** ( for better asyncio performance )
- **MultiProcessing** ( multiples processes using same port )
- **Thread poll workers** (use thread to decode large events >4kb)

Python is not good for performance but with this architecture We managed to turn it into something with high performance.

- **uvloop**: uses libuv (C library used in nodejs) under the hood, this increases the speed of all async tasks.
- **asyncio**: The project has used asyncio from the start.
- **caching**: I made many caching options on the project, this increases the speed for AES computation, database, etc.
- **workers**: workers for log decoding are default. by default it uses all cpus core.
- **multiprocessing**: by default I added 1 process to handle the connections, but you can increase with the option `--processes`.

## Setup development environment

Install **uv**

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Sync the project 

```sh
uv sync
```

Create the SSL pem

```
./scripts/generate_ssl.sh
```

Now you can run the server

```sh
uv run src/wazoo.py -v
```

# Test

You can test server using docker to run a wazuh agent.

```sh
uv run src/wazoo.py -v &
docker compose -f docker/agent.yml up 
```

# Conclusion

I dedicated a lot of my time to making this project and tutorial.

I want to do many different things in this project, one thing is implementing a HTTP Api to manage the server, but will do this only if the project get more visibility.

If you want me to continue developing this project, please consider to give a Star :star:

# Contact

If you want to contact me, you can use this options.
**E-mail**: me@souzo.me
**Matrix**: @souzo:matrix.org
**Linkedin**: https://www.linkedin.com/in/vinicius-m-a76ba51b5/
**Twitter/X**: https://x.com/souzomain
**Reddit**: https://www.reddit.com/user/_souzo/
