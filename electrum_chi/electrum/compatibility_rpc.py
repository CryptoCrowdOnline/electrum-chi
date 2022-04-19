# -*- coding: utf-8 -*-
#
# Electrum-CHI - lightweight Xaya client
# Copyright (C) 2019-2022 The Xaya developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
A JSON-RPC server that implements methods required by games in exactly the
same way as Xaya Core does, executing them based on Electrum.  This server
can be run in addition to the "standard" Electrum JSON-RPC server, and
allows to connect games to Electrum that are originally written for the
Xaya Core JSON-RPC interface.
"""

from . import bitcoin
from . import crypto
from . import ecc
from . import util

from .bitcoin import COIN
from .commands import Commands
from .logging import Logger

import jsonrpcserver
from jsonrpcserver import response

from aiohttp import web
import base64


class Logic (Logger):
  """
  The implementation of the actual RPC methods, but separated from the
  server itself.
  """

  commands = [
    "getbalance",
    "getblockcount",
    "getnewaddress",
    "sendtoaddress",
    "validateaddress",
    "signmessage",
    "verifymessage",
    "name_show",
    "name_list",
    "name_pending",
    "name_register",
    "name_update",
  ]

  def __init__ (self, cmd_runner):
    Logger.__init__ (self)
    self.cmd_runner = cmd_runner

    self.methods = jsonrpcserver.methods.Methods ()
    for cmdname in self.commands:
      self.methods.add (getattr (self, cmdname))

  def interpretNameOpOptions (self, opt):
    """
    Interprets the "options" argument to a name operation RPC and
    translates it to a dict of keyword arguments that should be passed
    to the corresponding Electrum command.
    """

    if opt is None:
      return {}

    res = {}
    for nm, val in opt.items ():
      if nm == "destAddress":
        res["destination"] = val
      elif nm == "sendCoins":
        res["outputs"] = list (val.items ())
      elif nm == "burn":
        res["burns"] = [(d.encode ("ascii"), COIN * n) for d, n in val.items ()]
      else:
        self.logger.warning (f"Unknown name-operation option: {nm}")

    return res

  async def getbalance (self):
    bal = await self.cmd_runner.getbalance ()

    res = 0
    for key in ["confirmed", "unconfirmed"]:
      if key in bal:
        res += float (bal[key])

    return res

  async def getblockcount (self):
    return self.cmd_runner.network.get_local_height ()

  async def getnewaddress (self, label="", address_type=None):
    addr = await self.cmd_runner.createnewaddress ()

    if address_type is None:
      return addr

    if address_type == "legacy":
      if addr.startswith("chi") or addr[0] not in ['C', 'c']:
        raise RuntimeError ("Cannot produce legacy address from this wallet")
      return addr

    raise RuntimeError (f"Unsupported address type: {address_type}")

  async def sendtoaddress (self, address, amount):
    tx = await self.cmd_runner.payto (address, amount)
    return await self.cmd_runner.broadcast (tx["hex"])

  async def validateaddress (self, address):
    valid = await self.cmd_runner.validateaddress (address)
    return {
      "address": address,
      "isvalid": valid,
    }

  async def signmessage (self, address, message):
    return await self.cmd_runner.signmessage (address, message)

  async def verifymessage (self, address, signature, message):
    # We need to handle the special form with address recovery supported
    # by Xaya Core.
    if address == "":
      sig = base64.b64decode (signature)
      msg_hash = crypto.sha256d (ecc.msg_magic (util.to_bytes (message)))
      pubkey, comp = ecc.ECPubkey.from_signature65 (sig, msg_hash)
      address = bitcoin.public_key_to_p2pkh (pubkey.get_public_key_bytes (comp))
      addr_recovery = True
    else:
      addr_recovery = False

    res = await self.cmd_runner.verifymessage (address, signature, message)
    if not addr_recovery:
      return res

    return {"valid": res, "address": address}

  async def name_show (self, name):
    return await self.cmd_runner.name_show (name)

  async def name_list (self, name=None):
    return await self.cmd_runner.name_list (name)

  async def name_pending (self, name=None):
    self.logger.warning ("name_pending is not supported properly,"
                         " returning empty mempool")
    return []

  async def name_register (self, name, value, options=None):
    opts = self.interpretNameOpOptions (options)
    tx = await self.cmd_runner.name_register (name, value, **opts)
    await self.cmd_runner.addtransaction (tx["hex"])
    return await self.cmd_runner.broadcast (tx["hex"])

  async def name_update (self, name, value, options=None):
    opts = self.interpretNameOpOptions (options)
    tx = await self.cmd_runner.name_update (name, value, **opts)
    await self.cmd_runner.addtransaction (tx["hex"])
    return await self.cmd_runner.broadcast (tx["hex"])
