#!/usr/bin/env python3

# This file is part of the Trezor project.
#
# Copyright (C) 2012-2019 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import json
import os
import sys

import click

from .. import coins, log, messages, protobuf, ui
from ..client import TrezorClient
from ..transport import enumerate_devices, get_transport
from . import (
    binance,
    btc,
    cardano,
    cosi,
    crypto,
    device,
    eos,
    ethereum,
    fido,
    firmware,
    lisk,
    monero,
    nem,
    ripple,
    settings,
    stellar,
    tezos,
)

COMMAND_ALIASES = {
    "change-pin": settings.pin,
    "enable-passphrase": settings.passphrase_enable,
    "disable-passphrase": settings.passphrase_disable,
    "set-passphrase-source": settings.passphrase_source,
    "wipe-device": device.wipe,
    "reset-device": device.setup,
    "recovery-device": device.recover,
    "backup-device": device.backup,
    "sd-protect": device.sd_protect,
    "load-device": device.load,
    "self-test": device.self_test,
    "get-entropy": crypto.get_entropy,
    "encrypt-keyvalue": crypto.encrypt_keyvalue,
    "decrypt-keyvalue": crypto.decrypt_keyvalue,
    # currency name aliases:
    "bnb": binance.cli,
    "eth": ethereum.cli,
    "ada": cardano.cli,
    "lsk": lisk.cli,
    "xmr": monero.cli,
    "xrp": ripple.cli,
    "xlm": stellar.cli,
    "xtz": tezos.cli,
}


class TrezorctlGroup(click.Group):
    """Command group that handles compatibility for trezorctl.

    The purpose is twofold: convert underscores to dashes, and ensure old-style commands
    still work with new-style groups.

    Click 7.0 silently switched all underscore_commands to dash-commands.
    This implementation of `click.Group` responds to underscore_commands by invoking
    the respective dash-command.

    With trezorctl 0.11.5, we started to convert old-style long commands
    (such as "binance-sign-tx") to command groups ("binance") with subcommands
    ("sign-tx"). The `TrezorctlGroup` can perform subcommand lookup: if a command
    "binance-sign-tx" does not exist in the default group, it tries to find "sign-tx"
    subcommand of "binance" group.
    """

    def get_command(self, ctx, cmd_name):
        cmd_name = cmd_name.replace("_", "-")
        # try to look up the real name
        cmd = super().get_command(ctx, cmd_name)
        if cmd:
            return cmd

        # look for a backwards compatibility alias
        if cmd_name in COMMAND_ALIASES:
            return COMMAND_ALIASES[cmd_name]

        # look for subcommand in btc - "sign-tx" is now "btc sign-tx"
        cmd = btc.cli.get_command(ctx, cmd_name)
        if cmd:
            return cmd

        # Old-style top-level commands looked like this: binance-sign-tx.
        # We are moving to 'binance' command with 'sign-tx' subcommand.
        try:
            command, subcommand = cmd_name.split("-", maxsplit=1)
            return super().get_command(ctx, command).get_command(ctx, subcommand)
        except Exception:
            pass

        # try to find a bitcoin-like coin whose shortcut matches the command
        for coin in coins.coins_list:
            if cmd_name.lower() == coin["shortcut"].lower():
                btc.DEFAULT_COIN = coin["coin_name"]
                return btc.cli

        return None


def configure_logging(verbose: int):
    if verbose:
        log.enable_debug_output(verbose)
        log.OMITTED_MESSAGES.add(messages.Features)


@click.command(cls=TrezorctlGroup, context_settings={"max_content_width": 400})
@click.option(
    "-p",
    "--path",
    help="Select device by specific path.",
    default=os.environ.get("TREZOR_PATH"),
)
@click.option("-v", "--verbose", count=True, help="Show communication messages.")
@click.option(
    "-j", "--json", "is_json", is_flag=True, help="Print result as JSON object"
)
@click.version_option()
@click.pass_context
def cli(ctx, path, verbose, is_json):
    configure_logging(verbose)

    def get_device():
        try:
            device = get_transport(path, prefix_search=False)
        except Exception:
            try:
                device = get_transport(path, prefix_search=True)
            except Exception:
                click.echo("Failed to find a Trezor device.")
                if path is not None:
                    click.echo("Using path: {}".format(path))
                sys.exit(1)
        return TrezorClient(transport=device, ui=ui.ClickUI())

    ctx.obj = get_device


@cli.resultcallback()
def print_result(res, path, verbose, is_json):
    if is_json:
        if isinstance(res, protobuf.MessageType):
            click.echo(json.dumps({res.__class__.__name__: res.__dict__}))
        else:
            click.echo(json.dumps(res, sort_keys=True, indent=4))
    else:
        if isinstance(res, list):
            for line in res:
                click.echo(line)
        elif isinstance(res, dict):
            for k, v in res.items():
                if isinstance(v, dict):
                    for kk, vv in v.items():
                        click.echo("%s.%s: %s" % (k, kk, vv))
                else:
                    click.echo("%s: %s" % (k, v))
        elif isinstance(res, protobuf.MessageType):
            click.echo(protobuf.format_message(res))
        else:
            click.echo(res)


#
# Common functions
#


@cli.command(name="list")
def list_devices():
    """List connected Trezor devices."""
    return enumerate_devices()


@cli.command()
def version():
    """Show version of trezorctl/trezorlib."""
    from trezorlib import __version__ as VERSION

    return VERSION


#
# Basic device functions
#


@cli.command()
@click.argument("message")
@click.option("-b", "--button-protection", is_flag=True)
@click.option("-p", "--pin-protection", is_flag=True)
@click.option("-r", "--passphrase-protection", is_flag=True)
@click.pass_obj
def ping(connect, message, button_protection, pin_protection, passphrase_protection):
    """Send ping message."""
    return connect().ping(
        message,
        button_protection=button_protection,
        pin_protection=pin_protection,
        passphrase_protection=passphrase_protection,
    )


@cli.command()
@click.pass_obj
def clear_session(connect):
    """Clear session (remove cached PIN, passphrase, etc.)."""
    return connect().clear_session()


@cli.command()
@click.pass_obj
def get_features(connect):
    """Retrieve device features and settings."""
    return connect().features


@cli.command()
def usb_reset():
    """Perform USB reset on stuck devices.

    This can fix LIBUSB_ERROR_PIPE and similar errors when connecting to a device
    in a messed state.
    """
    from trezorlib.transport.webusb import WebUsbTransport

    WebUsbTransport.enumerate(usb_reset=True)


#
# Basic coin functions
#

cli.add_command(binance.cli)
cli.add_command(btc.cli)
cli.add_command(cardano.cli)
cli.add_command(cosi.cli)
cli.add_command(crypto.cli)
cli.add_command(device.cli)
cli.add_command(eos.cli)
cli.add_command(ethereum.cli)
cli.add_command(fido.cli)
cli.add_command(lisk.cli)
cli.add_command(monero.cli)
cli.add_command(nem.cli)
cli.add_command(ripple.cli)
cli.add_command(settings.cli)
cli.add_command(stellar.cli)
cli.add_command(tezos.cli)

cli.add_command(firmware.firmware_update)


# Ontology functions
#


@cli.command(help="Get Ontology address for specified path.")
@click.option(
    "-n", "--address", required=True, help="BIP-32 path, e.g. m/44'/888'/0'/0/0"
)
@click.option("-d", "--show-display", is_flag=True)
@click.pass_obj
def ontology_get_address(connect, address, show_display):
    client = connect()
    address_n = tools.parse_path(address)
    return ontology.get_address(client, address_n, show_display)


@cli.command(help="Get Ontology public key for specified path.")
@click.option(
    "-n", "--address", required=True, help="BIP-32 path, e.g. m/44'/888'/0'/0/0"
)
@click.option("-d", "--show-display", is_flag=True)
@click.pass_obj
def ontology_get_public_key(connect, address, show_display):
    client = connect()
    address_n = tools.parse_path(address)
    result = ontology.get_public_key(client, address_n, show_display)

    return result.public_key.hex()


@cli.command(help="Sign Ontology transfer.")
@click.option(
    "-n",
    "--address",
    required=True,
    help="BIP-32 path to signing key, e.g. m/44'/888'/0'/0/0",
)
@click.option(
    "-t",
    "--transaction",
    type=click.File("r"),
    default="-",
    help="Transaction in JSON format",
)
@click.option(
    "-r",
    "--transfer",
    type=click.File("r"),
    default="-",
    help="Transfer in JSON format",
)
@click.pass_obj
def ontology_sign_transfer(connect, address, transaction, transfer):
    client = connect()
    address_n = tools.parse_path(address)
    transaction = protobuf.dict_to_proto(
        proto.OntologyTransaction, json.load(transaction)
    )
    transfer = protobuf.dict_to_proto(proto.OntologyTransfer, json.load(transfer))

    result = ontology.sign_transfer(client, address_n, transaction, transfer)

    output = {"payload": result.payload.hex(), "signature": result.signature.hex()}

    return output


@cli.command(help="Sign Ontology withdraw Ong.")
@click.option(
    "-n",
    "--address",
    required=True,
    help="BIP-32 path to signing key, e.g. m/44'/888'/0'/0/0",
)
@click.option(
    "-t",
    "--transaction",
    type=click.File("r"),
    default="-",
    help="Transaction in JSON format",
)
@click.option(
    "-w",
    "--withdraw_ong",
    type=click.File("r"),
    default="-",
    help="Withdrawal in JSON format",
)
@click.pass_obj
def ontology_sign_withdraw_ong(connect, address, transaction, withdraw_ong):
    client = connect()
    address_n = tools.parse_path(address)
    transaction = protobuf.dict_to_proto(
        proto.OntologyTransaction, json.load(transaction)
    )
    withdraw_ong = protobuf.dict_to_proto(
        proto.OntologyWithdrawOng, json.load(withdraw_ong)
    )

    result = ontology.sign_withdrawal(client, address_n, transaction, withdraw_ong)

    output = {"payload": result.payload.hex(), "signature": result.signature.hex()}

    return output


@cli.command(help="Sign Ontology ONT ID Registration.")
@click.option(
    "-n",
    "--address",
    required=True,
    help="BIP-32 path to signing key, e.g. m/44'/888'/0'/0/0",
)
@click.option(
    "-t",
    "--transaction",
    type=click.File("r"),
    default="-",
    help="Transaction in JSON format",
)
@click.option(
    "-r",
    "--register",
    type=click.File("r"),
    default="-",
    help="Register in JSON format",
)
@click.argument("transaction")
@click.argument("ont_id_register")
@click.pass_obj
def ontology_sign_ont_id_register(connect, address, transaction, register):
    client = connect()
    address_n = tools.parse_path(address)
    transaction = protobuf.dict_to_proto(
        proto.OntologyTransaction, json.load(transaction)
    )
    ont_id_register = protobuf.dict_to_proto(
        proto.OntologyOntIdRegister, json.load(register)
    )

    result = ontology.sign_register(client, address_n, transaction, ont_id_register)

    output = {"payload": result.payload.hex(), "signature": result.signature.hex()}

    return output


@cli.command(help="Sign Ontology ONT ID Attributes adding.")
@click.option(
    "-n",
    "--address",
    required=True,
    help="BIP-32 path to signing key, e.g. m/44'/888'/0'/0/0",
)
@click.option(
    "-t",
    "--transaction",
    type=click.File("r"),
    required=True,
    default="-",
    help="Transaction in JSON format",
)
@click.option(
    "-a",
    "--add_attribute",
    type=click.File("r"),
    required=True,
    default="-",
    help="Add attributes in JSON format",
)
@click.pass_obj
def ontology_sign_ont_id_add_attributes(connect, address, transaction, add_attr):
    client = connect()
    address_n = tools.parse_path(address)
    transaction = protobuf.dict_to_proto(
        proto.OntologyTransaction, json.load(transaction)
    )
    ont_id_add_attributes = protobuf.dict_to_proto(
        proto.OntologyOntIdAddAttributes, json.load(add_attr)
    )
    result = ontology.sign_add_attr(
        client, address_n, transaction, ont_id_add_attributes
    )
    output = {"payload": result.payload.hex(), "signature": result.signature.hex()}

    return output


#
# Main
#


if __name__ == "__main__":
    cli()  # pylint: disable=E1120
