<center>

### BTest Server

> BTestServer is a Rust-based server application designed for conducting bandwidth tests with RouterOS devices. It enables communication over TCP and UDP, supports optional authentication, and dynamically allocates ports for flexibility.

</center>
## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Features](#features)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Overview

BTestServer serves as a bandwidth testing tool specifically tailored for RouterOS devices. It facilitates secure communication over TCP and UDP, offering optional authentication and dynamic port handling to ensure a smooth testing experience.

## Prerequisites

Ensure you have the following dependencies installed before running BTestServer:

- [dotenv](https://crates.io/crates/dotenv)
- [hex](https://crates.io/crates/hex)
- [md5](https://crates.io/crates/md5)
- [rand](https://crates.io/crates/rand)

## Installation

Clone the BTestServer repository and build the project:

```bash
git clone https://github.com/your-username/BTestServer.git
cd BTestServer
cargo build .
```

## Configuration

Set the following environment variables in `.env` for configuration:

- `USERNAME`: The username for RouterOS authentication (default: "btest").
- `PASSWORD`: The password for RouterOS authentication (default: "btest").
- `AUTH`: Enable or disable authentication (default: true).

```env
USERNAME="your_routeros_username"
PASSWORD="your_routeros_password"
AUTH="true"
```

## Usage

Run BTestServer using the following command:

```bash
cargo run .
```

## Features

- **Authentication**: Secure communication with optional RouterOS authentication.
- **Protocol Support**: Supports both TCP and UDP protocols for conducting bandwidth tests.
- **Dynamic Port Handling**: Dynamically allocates ports based on the specified protocol for flexibility during testing.

## Testing

Run the tests to ensure the reliability of the application:

```bash
cargo test
```

## Contributing

Contributions to BTestServer are welcome.

## License

BTestServer is licensed under the [MIT License](LICENSE).