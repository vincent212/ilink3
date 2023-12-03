# CME ilink3 protocol Coder/Decoder
CME order managment iLink3 codec

This repo contain a codec for the CME iLink3 protocol. It is everything you will need to 
translate C++ structures into iLink messagesa and the other way around.

This is not a complete implementation of an iLink order manager. It is just the layer
on top of which an iLink handler can be implemented.

You will need to generate SBE headers to use the codec. This is done using the SBE generator
and the iLink message schema provided by the CME.

What is in the files:

ILinkCBIF.hpp: The interface you will need to implement to receive messages from iLink

ILinkRcv.hpp: Functions that actually receive messages from iLink and call the interface

iLinkSnd: Code to create iLink messages

socke_help.hpp: Code to handle the CME socket

audit.hpp: Audit trail stuff

ilink_null.hpp: Definitions of NULL values

sign.hpp: for signing iLink messages
