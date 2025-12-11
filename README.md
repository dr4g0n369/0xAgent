# 0xAgent

## Project Overview

Hacker Agent is an automated system designed to analyze and solve Capture The Flag (CTF) challenges.

Currently, the agent can successfully solve the following challenges from the [Electrovoltsec/HackBench](https://github.com/Electrovoltsec/HackBench) repository:
- `EV-01`
- `EV-02`
- `EV-03`
- `EV-05`
- `EV-06`
- `EV-15`

## Getting Started

### Installation & Setup

1.  **Create and activate a Python virtual environment:**
    ```sh
    cd hacker-agent
    python3 -m venv venv
    source ./venv/bin/activate
    ```

2.  **Install the required dependencies:**
    ```sh
    pip install -r requirements.txt
    ```

## Usage

The script requires a source directory containing the challenge's `docker-compose.yaml` file and an `application` folder with the source code.

### Command-Line Arguments

```sh
usage: hacker_agent.py [-h] [--src-dir SRC_DIR] [--flag-format FLAG_FORMAT]

A multi-agent system for solving CTF challenges.

options:
  -h, --help            show this help message and exit
  --src-dir SRC_DIR     Path to the directory containing docker-compose.yaml and the 'application' source code. (Default: src)
  --flag-format FLAG_FORMAT
                        The expected starting format of the flag (e.g., 'ev', 'flag'). (Default: ev)
```

### Running the Agent

Make sure to start the challenge first using the below command
```sh
docker compose up
```

Create a `.env` file with containing your `GOOGLE_API_KEY`
```
GOOGLE_API_KEY=<api-key>
```

To run the agent with the default settings (`--src-dir src` and `--flag-format ev`):
```sh
python hacker_agent.py
```

To specify a different challenge directory:
```sh
python hacker_agent.py --src-dir /path/to/your/challenge
```

## Personal Views

I haven't had this much fun working on a project in a long time. Solving challenges has always been rewarding, but this was my first time trying to build an automated system that tackles a problem on its own. I’ve come to realize that creating an AI that can "just do things" is far from simple.