#!/usr/bin/env python3

import socks
import json
import click
from libs.connections import send, receive


class Config:
    def __init__(self, mode, host, timeout):
        self.timeout = timeout
        self.host = host

        if mode == "regnet":
            self.port = 3030
            self.is_regnet = True

        elif mode == "testnet":
            self.port = 2829
            self.is_testnet = True

        elif mode == "mainnet":
            self.port = 5658


def load_local_address(keyfile="wallet.der"):
    with open(keyfile, "r") as keyfile:
        wallet_dict = json.load(keyfile)
    address = wallet_dict["Address"]
    return address


local_address = load_local_address()


@click.group()
@click.option("--mode", "-m", default="mainnet", help="mainnet, testnet, regnet")
@click.option("--host", "-h", default="127.0.0.1", help="IP")
@click.option("--timeout", "-t", default=30, help="Timeout in seconds")
# @click.option("--format", "-f", is_flag=True) #  not implemented yet
@click.pass_context
def cli(ctx, mode, host, timeout):
    ctx.obj = Config(mode, host, timeout)


@cli.command()
@click.argument("command", nargs=-1)
@click.pass_context
def forward(**kwargs):
    """Directly forwards commands"""

    commands = kwargs.get("command")  # extract kwarg
    ctx = kwargs.get("ctx")  # extract kwarg

    key_command = commands[0]
    extra_args = commands[1:]

    response = send_command(ctx, key_command, extra_args)
    click.echo(response)


def send_command(ctx, key, extra_args_input=None, return_answer=True):
    """Handles connection, sending and receiving"""
    s = socks.socksocket()
    s.connect((ctx.obj.host, ctx.obj.port))

    print(key)
    send(s, key)

    if extra_args_input and type(extra_args_input) is list:
        for extra_arg in extra_args_input:
            send(s, extra_arg)
    elif extra_args_input and type(extra_args_input) in [str, tuple]:
        send(s, extra_args_input)

    if return_answer:
        response = receive(s, timeout=ctx.obj.timeout)
        return response
    else:
        return None


@cli.command()
@click.pass_context
def api_getconfig(ctx):
    """Configuration"""
    click.echo(send_command(ctx=ctx, key="api_getconfig"))


@cli.command()
@click.pass_context
def diffget(ctx):
    """Realtime difficulty, used in mining"""
    click.echo(send_command(ctx=ctx, key="diffget"))


@cli.command()
@click.pass_context
def diffgetjson(ctx):
    """JSON realtime difficulty, used in mining"""
    click.echo(send_command(ctx=ctx, key="diffgetjson"))


@cli.command()
@click.argument("address", type=str, default=local_address)
@click.pass_context
def balanceget(ctx, address):
    """Balance of a particular address"""
    click.echo(send_command(ctx=ctx, key="balanceget", extra_args_input=address))


@cli.command()
@click.argument("address", type=str, default=local_address)
@click.pass_context
def balancegetjson(ctx, address):
    """JSON balance of a particular address"""
    click.echo(send_command(ctx=ctx, key="balancegetjson", extra_args_input=address))


@cli.command()
@click.argument("address", type=str, default=local_address)
@click.pass_context
def balancegethyper(ctx, address):
    """Balance of a particular address in hyperledger"""
    click.echo(send_command(ctx=ctx, key="balancegethyper", extra_args_input=address))


@cli.command()
@click.argument("address", type=str, default=local_address)
@click.pass_context
def balancegethyperjson(ctx, address):
    """JSON balance of a particular address in hyperledger"""
    click.echo(
        send_command(ctx=ctx, key="balancegethyperjson", extra_args_input=address)
    )


@cli.command()
@click.argument("transaction")
@click.pass_context
def mpinsert(ctx, transaction):
    """Insert raw transaction into the mempool"""
    click.echo(send_command(ctx=ctx, key="mpinsert", extra_args_input=transaction))


@cli.command()
@click.pass_context
def mpget(ctx):
    """Current mempool content"""
    click.echo(send_command(ctx=ctx, key="mpget"))


@cli.command()
@click.pass_context
def mpgetjson(ctx):
    """JSON current mempool content"""
    click.echo(send_command(ctx=ctx, key="mpgetjson"))


@cli.command()
@click.pass_context
def difflast(ctx):
    """Last mined difficulty"""
    click.echo(send_command(ctx=ctx, key="difflast"))


@cli.command()
@click.pass_context
def difflastjson(ctx):
    """JSON Last mined difficulty"""
    click.echo(send_command(ctx=ctx, key="difflastjson"))


@cli.command()
@click.pass_context
def blocklast(ctx):
    """Last block content"""
    click.echo(send_command(ctx=ctx, key="blocklast"))


@cli.command()
@click.pass_context
def blocklastjson(ctx):
    """JSON Last block content"""
    click.echo(send_command(ctx=ctx, key="blocklastjson"))


@cli.command()
@click.argument("since")
@click.pass_context
def api_getblocksince(ctx, since=None):
    """Block since"""
    click.echo(send_command(ctx=ctx, key="api_getblocksince", extra_args_input=since))


@cli.command()
@click.pass_context
def keygen(ctx):
    """Generate RSA key pairs"""
    click.echo(send_command(ctx=ctx, key="keygen"))


@cli.command()
@click.pass_context
def keygenjson(ctx):
    """JSON generate RSA key pairs"""
    click.echo(send_command(ctx=ctx, key="keygenjson"))


@cli.command()
@click.argument("height")
@click.pass_context
def blockget(ctx, height):
    """Get block from a particular height"""
    click.echo(send_command(ctx=ctx, key="blockget", extra_args_input=height))


@cli.command()
@click.argument("height")
@click.pass_context
def blockgetjson(ctx, height):
    """JSON block from a particular height"""
    click.echo(send_command(ctx=ctx, key="blockgetjson", extra_args_input=height))


@cli.command()
@click.argument("address", type=str, default=local_address)
@click.pass_context
def addlist(ctx, address):
    """All transactions of an address"""
    click.echo(send_command(ctx=ctx, key="addlist", extra_args_input=address))


@cli.command()
@click.argument("address", type=str, default=local_address)
@click.argument("limit")
@click.pass_context
def addlistlim(ctx, address, limit):
    """Given number of transactions of an address"""
    click.echo(
        send_command(ctx=ctx, key="addlistlim", extra_args_input=[address, limit])
    )


@cli.command()
@click.argument("address", type=str, default=local_address)
@click.argument("limit")
@click.pass_context
def addlistlimjson(ctx, address, limit):
    """JSON given number of transactions of an address"""
    click.echo(
        send_command(ctx=ctx, key="addlistlimjson", extra_args_input=[address, limit])
    )


@cli.command()
@click.argument("address", type=str, default=local_address)
@click.argument("limit")
@click.pass_context
def addlistlimmir(ctx, address, limit):
    """Given number of mirror transactions of an address"""
    click.echo(
        send_command(ctx=ctx, key="addlistlimmir", extra_args_input=[address, limit])
    )


@cli.command()
@click.argument("address", type=str, default=local_address)
@click.argument("limit")
@click.pass_context
def addlistlimmirjson(ctx, address, limit):
    """JSON Given number of mirror transactions of an address"""
    click.echo(
        send_command(
            ctx=ctx, key="addlistlimmirjson", extra_args_input=[address, limit]
        )
    )


@cli.command()
@click.argument("limit")
@click.pass_context
def listlim(ctx, limit):
    """Given number of last transactions"""
    click.echo(send_command(ctx=ctx, key="listlim", extra_args_input=limit))


@cli.command()
@click.argument("limit")
@click.pass_context
def listlimjson(ctx, limit):
    """JSON given number of last transactions"""
    click.echo(send_command(ctx=ctx, key="limit", extra_args_input=limit))


@cli.command()
@click.argument("hash")
@click.pass_context
def api_getblockfromhash(ctx, hash_to_seek):
    """Retrieve block contents based on block hash"""
    click.echo(
        send_command(ctx=ctx, key="api_getblockfromhash", extra_args_input=hash_to_seek)
    )


@cli.command()
@click.argument(
    "transaction: (str(timestamp), "
    "str(private_key), "
    "str(recipient), "
    "str(amount), "
    "str(operation), "
    "str(data))",
    nargs=1,
)
@click.pass_context
def txsend(ctx, timestamp, private_key, recipient, amount, operation, data):
    click.echo(
        send_command(
            ctx=ctx,
            key="txsend",
            extra_args_input=(
                str(timestamp),
                str(private_key),
                str(recipient),
                str(amount),
                str(operation),
                str(data),
            ),
        )
    )


@cli.command()
@click.argument("address", type=str, default=local_address)
@click.pass_context
def aliasget(ctx, address):
    """Retrieve all aliases for a given address"""
    click.echo(send_command(ctx=ctx, key="aliasget", extra_args_input=address))


@cli.command()
@click.argument("address", type=str, default=local_address)
@click.pass_context
def tokensget(ctx, address):
    """Retrieve tokens for a given address"""
    click.echo(send_command(ctx=ctx, key="tokensget", extra_args_input=address))


@cli.command()
@click.argument("alias")
@click.pass_context
def addfromalias(ctx, alias):
    """Retrieve an alias which is matching the given address"""
    click.echo(send_command(ctx=ctx, key="tokensget", extra_args_input=alias))


@cli.command()
@click.pass_context
def peersget(ctx):
    """Retrieve list of peers"""
    click.echo(send_command(ctx=ctx, key="peersget"))


@cli.command()
@click.pass_context
def statusget(ctx):
    """Retrieve status"""
    click.echo(send_command(ctx=ctx, key="statusget"))


@cli.command()
@click.pass_context
def stop(ctx):
    """Ask the node to close nicely"""
    click.echo(send_command(ctx=ctx, key="stop", return_answer=False))

@cli.command()
@click.pass_context
def portget(ctx):
    """Retrieve port on which the node is running"""
    click.echo(send_command(ctx=ctx, key="portget"))


@cli.command()
@click.argument("address", type=str, default=local_address)
@click.pass_context
def addvalidate(ctx, address):
    """Validate a given address"""
    click.echo(send_command(ctx=ctx, key="tokensget", extra_args_input=address))


@cli.command()
@click.pass_context
def aliasesget(ctx, aliases):
    """Retrieve addresses for multiple aliases"""
    aliases_list = aliases.split(",")
    click.echo(send_command(ctx=ctx, key="aliasesget", extra_args_input=aliases_list))


def api_getaddresssince(ctx, since_height, minconf, address):
    """
    Returns the full transactions following a given block_height (will not include the given height) for the given address, with at least min_confirmations confirmations,
    as well as last considered block.
    Returns at most transactions from 720 blocks at a time (the most *older* ones if it truncates) so about 12 hours worth of data.
    """
    click.echo(
        send_command(
            ctx=ctx,
            key="api_getaddresssince",
            extra_args_input=[since_height, minconf, address],
        )
    )


@cli.command()
@click.pass_context
def getversion(ctx):
    """Retrieve node version"""
    click.echo(send_command(ctx=ctx, key="getversion"))


@cli.command()
@click.argument("number")
@click.pass_context
def regtest_generate(ctx, number):
    """Mine blocks in regnet"""
    if ctx.obj.is_regnet:
        click.echo(
            send_command(ctx=ctx, key="regtest_generate", extra_args_input=number)
        )


if __name__ == "__main__":
    cli()
