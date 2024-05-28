# VelociFix - Vulnerability detection and patching

[Velociraptor](https://github.com/Velocidex/velociraptor) is an advanced DFIR tool that provides multiple endpoint monitoring with key functionalities suitable for business or domestic enviroments.

Velocifix offers a first approach to the possibility of using Velociraptor as a means for detecting vulnerabilities in applications installed on monitored clients, as well as the capability to remediate these vulnerabilities by deploying automatic updates through a private repository where the latest versions can be stored and downloaded.

## What you need

For this prototype to function correctly in your business or home environment, the following requirements must be met:

- A **Velociraptor service** configured and running.
- At least one **Windows client** connected to the server. Furthermore, this client **must** have *Powershell 7.4.2* or higher installed and included in its `$PATH`. You can test it by opening the Windows terminal and running `pwsh`.
- An **API configuration file** that allows requests to the server. This file can be generated as shown in the Velociraptor [documentation](https://docs.velociraptor.app/docs/server_automation/server_api/).
- Enter the GUI of the Velociraptor server, and create the [artifact](./artifact.vql) needed to retrieve the apps.

## How it works

## Server configuration
As shown in the [previous](./README.md#how-it-works) section, for this PoC to be able to perform both detection and patching of vulnerabilities, a server must be configured to serve as the storage for all the .msi files that will contain the latest versions.

You can read a full guide on how to configure this server [here]().

## Installation
Start by clonning the repository.
```
git clone https://github.com/AaronBlancoLopez/VelociFix.git
```
Go to the project folder and install all the dependencies.
```
cd VelociFix
pip3 install -r requirements.txt
```

## Usage
Once installed, you can start using Velocifix by simply running:
```
sudo python3 main.py --config [path to API file]
```
If everything worked fine, you should be presented with a terminal menu with two options.

1. Lists all currently connected clients.
2. Performs a scan to the selected client. This will list all apps installed on it and highlight any found vulnerabilities. If you configured the server, you can try and go through the next step, wich will search for the latest versions of the vulnerable apps and install them if found.