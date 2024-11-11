#!/usr/bin/python3

import time
import json
import grpc
import pyvelociraptor

from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc
from pprint import pprint

# establishes the connection to the Velociraptor server
def _connect_(config):
    config = pyvelociraptor.LoadConfigFile(config)
    creds = grpc.ssl_channel_credentials(
        root_certificates=config["ca_certificate"].encode("utf8"),
        private_key=config["client_private_key"].encode("utf8"),
        certificate_chain=config["client_cert"].encode("utf8"))
    options = (('grpc.ssl_target_name_override', "VelociraptorServer",),)
    channel = grpc.secure_channel(
            config["api_connection_string"],
            creds,
            options
        )
    return channel 


# performs a simple query to get the list of connected clients
def getClients(config):
    channel = _connect_(config)
    # query execution
    stub = api_pb2_grpc.APIStub(channel)
    request = api_pb2.VQLCollectorArgs(
        max_wait=1,
        max_row=100,
        Query=[api_pb2.VQLRequest(
            Name="GetClients",
            VQL="SELECT client_id FROM clients()")]
    )
    # response processing
    for response in stub.Query(request):
        if response.Response:
            package = json.loads(response.Response)
            client_ids = [client['client_id'] for client in package]
            return client_ids


# retrieves the client information for a specific client
def getClientInfo(config, client):
    channel = _connect_(config)
    # query definition
    vql_query = f"""
            SELECT client_id, agent_information, os_info 
            FROM clients() 
            WHERE client_id = '{client}'
            """
    # query execution
    stub = api_pb2_grpc.APIStub(channel)
    request = api_pb2.VQLCollectorArgs(
        max_wait=1,
        max_row=100,
        Query=[api_pb2.VQLRequest(
            Name="GetClients",
            VQL=vql_query)]
    )
    # response processing
    for response in stub.Query(request):
        if response.Response:
            package = json.loads(response.Response)
    return package


# retrieves the list of installed applications for a specific client
def getApps(config, client):
    channel = _connect_(config)
    # query definition
    vql_query = f"""
        LET collection <= collect_client(
                        client_id='{client}',
                        artifacts='Custom.RetrieveApps',
                        env=dict(file=file))

        LET _ <= SELECT *
        FROM watch_monitoring(artifact='System.Flow.Completion')
        WHERE FlowId = collection.flow_id
        LIMIT 1 

        SELECT *
        FROM source(client_id=collection.request.client_id,
                    flow_id=collection.flow_id,
                    artifact='Custom.RetrieveApps/X32')
        SELECT *
        FROM source(client_id=collection.request.client_id,
                    flow_id=collection.flow_id,
                    artifact='Custom.RetrieveApps/X64')
        """
    # query execution
    stub = api_pb2_grpc.APIStub(channel)
    request = api_pb2.VQLCollectorArgs(
        max_wait=1,
        max_row=100,
        Query=[api_pb2.VQLRequest(
            Name="GetApps",
            VQL=vql_query)]
    )
    # response processing
    packages = []
    for response in stub.Query(request):
        if response.Response:
            package = json.loads(response.Response)
            packages.append(package)
    return packages


# downloads a file from the app repository to a specific client
def download(config, client, app, repository):
    channel = _connect_(config)
    # query definition
    vql_query = f'''
        LET Command = "pwsh -Command '$cert=Get-ChildItem -Path Cert:\\\LocalMachine\\\My; Invoke-WebRequest -SkipCertificateCheck -Uri {repository}/{app}.msi -Certificate $cert -OutFile \\"C:/\\"'"
        LET collection <= collect_client(
            client_id='{client}',
            artifacts='Windows.System.PowerShell',
            env=dict(Command=Command))

        LET _ <= SELECT *
        FROM watch_monitoring(artifact='System.Flow.Completion')
        WHERE FlowId = collection.flow_id
        LIMIT 1 

        SELECT *
        FROM source(client_id=collection.request.client_id,
                    flow_id=collection.flow_id,
                    artifact='Windows.System.PowerShell')
        '''
    # query execution
    stub = api_pb2_grpc.APIStub(channel)
    request = api_pb2.VQLCollectorArgs(
        max_wait=1,
        max_row=100,
        Query=[api_pb2.VQLRequest(
            Name="download",
            VQL=vql_query)]
    )
    # response processing
    print(f" Looking for {repository}/{app}.msi")
    for response in stub.Query(request):
        if 'Not Found' in response.Response:
            return 1
        elif '"Stderr":""' in response.Response:
            return 0
    return -1


# installs an application on a specific client
def installation(config, client, app):
    channel = _connect_(config)
    # query definition
    vql_query = f'''
        LET Command = "cd 'C:/'; msiexec /i '{app}.msi'"
        LET collection <= collect_client(
            client_id='{client}',
            artifacts='Windows.System.PowerShell',
            env=dict(Command=Command))

        LET _ <= SELECT *
        FROM watch_monitoring(artifact='System.Flow.Completion')
        WHERE FlowId = collection.flow_id
        LIMIT 1 

        SELECT *
        FROM source(client_id=collection.request.client_id,
                    flow_id=collection.flow_id,
                    artifact='Windows.System.PowerShell')
        '''
    # query execution
    print(f"\n Installing {app} on {client}")
    stub = api_pb2_grpc.APIStub(channel)
    request = api_pb2.VQLCollectorArgs(
        max_wait=1,
        max_row=100,
        Query=[api_pb2.VQLRequest(
            Name="download",
            VQL=vql_query)]
    )
    # response processing
    for response in stub.Query(request):
        if response.Response:
            package = json.loads(response.Response)
    return package