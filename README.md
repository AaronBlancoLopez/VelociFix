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

Velociraptor provides an API that allows to manage and schedule collections remotely and without having to access the GUI.

On the other hand, [PyVelociraptor](https://pypi.org/project/pyvelociraptor/) provides the python bindings to that API, so you can script those collections.

### Detection

With this tools, VelociFix schedules and executes specific collections related to apps installed in every Windows client monitored. The information retrived is later used to serch for vulnerabilities in the [National Vulnerabilities Database](https://nvd.nist.gov/) hosted by the NIST, wich you can also access throug their API. 

<p align="center" width="100%">
    <img src="./assets/VelociFixArch.svg">
</p>

As you can see in the diagram, the Velociraptor service and Velocifix may or may not be running on the same machine, but this shouldn't be any problem if they are configured properly.

This flow covers only the first part of the functionality, where possible vulnerabilities are detected. At the end of this process, a .docx file is generated as a report, containing relevant info of the client, the software installed and the vulnerabilities found.

### Patching

The second part is to be able to download and install the latest version of any vulnerable software installed on the client.

VelociFix proposes a dinamically-filled server/repository as a solution. This repository is fed with .msi files that must be manually downloaded and stored in it by the administrator or some priviledge member.

In this [guide]() an apache2 server is configured to represent the repository, wich only allowed endpoints can access as the server is configured with certificate validation. Self-signed client certificates **must** be previously created and distributed to the clients.

<p align="center" width="100%">
    <img src="./assets/VelociFixSequence.svg">
</p>

The above diagram represents a common use case, where the requested app is not stored in the server, so it has to be filled by an administrator. 

## Server configuration

As shown in the [previous](./README.md#how-it-works) section, for this PoC to be able to perform both detection and patching of vulnerabilities, a server must be configured to serve as the storage for all the .msi files that will contain the latest versions.

This server will be configured with **mutual authentication**, so we have a way to control the acccess to the repository without having to store any kind of username/password. **Only clients who present the certificate will be allowed to access the repository**.

You can read a full guide on how to configure an apache server with mutual authentication [here](https://www.openlogic.com/blog/mutual-authentication-using-apache-and-web-client).

To test that your server is properly configured, you can try to access the repository and check that selecting the right certificate allows the connection to establish.

### Some mandatory rules

Once the server is up and working fine with mutual authentication, some extra configurations need to be taken in count:

1. The Velocirator queries (VQL) run through the `SYSTEM` user. This means we need to install the client certificate on the `\LocalMachine` folder of this user for the web requests to work.
2. As web requests are done automatically, a standard has to be set to control the names the apps will be given in the repository, so that the URL of the request is built properly. **If not, apps stored in the server may not be found**. In this way, the standard established is to use the first two (or only first, if second element is not a word) words of the name the software appears with in the generated report (which is the same as the *'DisplayName'* field of the app in the registry) with the space replaced by '_'. E.g. Mozilla Firefox (x64 es-ES) will be stored with the name Mozilla_Firefox. You can use the [monitor](monitor.py) script to see more clearly what applications are being requested to the server.

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
sudo python3 main.py --config [path to API file] --repository [optional][server URL]
```
If everything worked fine, you should be presented with a terminal menu with two options.

1. Lists all currently connected clients.
2. Performs a scan to the selected client. This will list all apps installed on it and highlight any found vulnerabilities. If you configured the server, you can try and go through the next step, wich will search for the latest versions of the vulnerable apps and install them if found.