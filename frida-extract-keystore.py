#!/usr/bin/python3

'''
author: ceres-c, JJK96
usage: ./frida-extract-keystore.py
       Once the keystore(s) have been exported you have to convert them to PKCS12 using keytool
'''

import frida, sys, time
import argparse
parser = argparse.ArgumentParser()
parser.add_argument("app_name")
args = parser.parse_args()

app_name = args.app_name
i = 0
ext = ''

def on_message(message, data):
    global i, ext
    if (message['type'] == 'send' and 'event' in message['payload']):
        if (message['payload']['event'] == '+found'):
            i += 1
            print("\n[+] Hooked keystore" + str(i) + "...")

        elif (message['payload']['event'] == '+type'):
            print("  [+] Cert Type: " + ''.join(message['payload']['certType']))
            if (message['payload']['certType'] == 'PKCS12'):
                ext = '.jks'

        elif (message['payload']['event'] == '+pass'):
            print("  [+] Password: " + ''.join(message['payload']['password']))

        elif (message['payload']['event'] == '+write'):
            print("  [+] Writing to file: keystore" + str(i) + ext)
            f = open('keystore' + str(i) + ext, 'wb')
            f.write(bytes.fromhex(message['payload']['cert']))
            f.close()
    else:
        print(message)


def on_diagnostics(diag):
    print("diag", diag)

compiler = frida.Compiler()
compiler.on("diagnostics", on_diagnostics)
bundle = compiler.build("agent/index.ts")

print("[.] Attaching to device...")
try:
    device = frida.get_usb_device()
except:
    print("[-] Can't attach. Is the device connected?")
    sys.exit()

print("[.] Spawning the app...")
try:
    pid = device.spawn(app_name)
except:
    print("[-] Can't spawn the App. Is filename correct?")
    sys.exit()

print("[.] Attaching to process...")
try:
    process = device.attach(pid)
except:
    print("[-] Can't connect to App.")
    sys.exit()

print("[.] Launching js code...")
print("  (run the app until needed, close it and then kill this script)")
script = process.create_script(bundle)
script.on('message', on_message)
script.load()

time.sleep(1)

device.resume(pid)

try:
	sys.stdin.read()
except KeyboardInterrupt:
    print ("\nExiting now")
    exit(0)
