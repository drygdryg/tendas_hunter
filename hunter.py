# -*- coding: utf-8 -*-
import subprocess
import re
import codecs


class WiFiScanner():
    """iw-based Wi-Fi networks scanner"""
    def __init__(self, interface):
        self.interface = interface

    def scan(self, dump_only=False):
        '''Parsing iw scan results'''
        def handle_network(line, result, networks):
            networks.append(
                    {
                        'Security type': 'Unknown',
                        'WPS': False,
                        'WPS state': False,
                        'WPS locked': False,
                        'Response type': False,
                        'UUID': '',
                        'Manufacturer': '',
                        'Model': '',
                        'Model number': '',
                        'Serial number': '',
                        'Primary device type': '',
                        'Device name': '',
                        'Config methods': []
                     }
                )
            networks[-1]['BSSID'] = result.group(1).upper()

        def handle_essid(line, result, networks):
            d = result.group(1)
            networks[-1]['ESSID'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_level(line, result, networks):
            networks[-1]['Level'] = int(float(result.group(1)))

        def handle_securityType(line, result, networks):
            sec = networks[-1]['Security type']
            if result.group(1) == 'capability':
                if 'Privacy' in result.group(2):
                    sec = 'WEP'
                else:
                    sec = 'Open'
            elif sec == 'WEP':
                if result.group(1) == 'RSN':
                    sec = 'WPA2'
                elif result.group(1) == 'WPA':
                    sec = 'WPA'
            elif sec == 'WPA':
                if result.group(1) == 'RSN':
                    sec = 'WPA/WPA2'
            elif sec == 'WPA2':
                if result.group(1) == 'WPA':
                    sec = 'WPA/WPA2'
            networks[-1]['Security type'] = sec

        def handle_wps(line, result, networks):
            networks[-1]['WPS'] = result.group(1)

        def handle_wpsState(line, result, networks):
            networks[-1]['WPS state'] = int(result.group(1))

        def handle_wpsLocked(line, result, networks):
            flag = int(result.group(1), 16)
            if flag:
                networks[-1]['WPS locked'] = True

        def handle_responseType(line, result, networks):
            networks[-1]['Response type'] = int(result.group(1))

        def handle_uuid(line, result, networks):
            d = result.group(1)
            networks[-1]['UUID'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_manufacturer(line, result, networks):
            d = result.group(1)
            networks[-1]['Manufacturer'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_model(line, result, networks):
            d = result.group(1)
            networks[-1]['Model'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_modelNumber(line, result, networks):
            d = result.group(1)
            networks[-1]['Model number'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_serialNumber(line, result, networks):
            d = result.group(1)
            networks[-1]['Serial number'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_primaryDeviceType(line, result, networks):
            networks[-1]['Primary device type'] = result.group(1)

        def handle_deviceName(line, result, networks):
            d = result.group(1)
            networks[-1]['Device name'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_configMethods(line, result, networks):
            networks[-1]['Config methods'] = result.group(1).split(', ')

        matchers = {
            re.compile(r'BSS (\S+)( )?\(on \w+\)'): handle_network,
            re.compile(r'SSID: (.*)'): handle_essid,
            re.compile(r'signal: ([+-]?([0-9]*[.])?[0-9]+) dBm'): handle_level,
            re.compile(r'(capability): (.+)'): handle_securityType,
            re.compile(r'(RSN):\t [*] Version: (\d+)'): handle_securityType,
            re.compile(r'(WPA):\t [*] Version: (\d+)'): handle_securityType,
            re.compile(r'WPS:\t [*] Version: (([0-9]*[.])?[0-9]+)'): handle_wps,
            re.compile(r' [*] Wi-Fi Protected Setup State: (\d)'): handle_wpsState,
            re.compile(r' [*] AP setup locked: (0x[0-9]+)'): handle_wpsLocked,
            re.compile(r' [*] Response Type: (\d)'): handle_responseType,
            re.compile(r' [*] UUID: (.*)'): handle_uuid,
            re.compile(r' [*] Manufacturer: (.*)'): handle_manufacturer,
            re.compile(r' [*] Model: (.*)'): handle_model,
            re.compile(r' [*] Model Number: (.*)'): handle_modelNumber,
            re.compile(r' [*] Serial Number: (.*)'): handle_serialNumber,
            re.compile(r' [*] Primary Device Type: (.*)'): handle_primaryDeviceType,
            re.compile(r' [*] Device name: (.*)'): handle_deviceName,
            re.compile(r' [*] Config methods: (.*)'): handle_configMethods
        }

        cmd = 'iw dev {} scan'.format(self.interface)
        if dump_only:
            cmd += ' dump'
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, encoding='utf-8')
        lines = proc.stdout.splitlines()
        networks = []

        for line in lines:
            if line.startswith('command failed:'):
                print(line)
                return False
            line = line.strip('\t')
            for regexp, handler in matchers.items():
                res = re.match(regexp, line)
                if res:
                    handler(line, res, networks)

        # Filtering non-WPS networks
        networks = list(filter(lambda x: bool(x['WPS']), networks))
        if not networks:
            return False

        # Sorting by signal level
        networks.sort(key=lambda x: x['Level'], reverse=True)
        return networks


def makeSound():
    cmd = 'termux-media-player play notification.ogg'
    subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)


def makeVibration():
    cmd = 'termux-vibrate'
    subprocess.run(cmd, shell=True)


def makeToast(text):
    cmd = 'termux-toast "{}"'.format(text)
    subprocess.run(cmd, shell=True)


if __name__ == '__main__':
    import argparse
    import json
    import time

    parser = argparse.ArgumentParser(
        description='Утилита для поиска роутеров Tenda.'
        'Использует iw для сканирования и получения информации о производителе, модели и пр. (WSC); '
        'Termux API для звуковых оповещений и вибрации.',
        epilog='Пример использования: %(prog)s -i wlan0 --sound --vibrate --toast')

    parser.add_argument(
        '-i', '--interface',
        type=str,
        required=True,
        help='Имя беспроводного интерфейса для сканирования'
        )
    parser.add_argument(
        '-m', '--mode',
        type=str,
        choices=['real', 'dump'],
        default='dump',
        help='Метод сканирования: real — настоящее сканирование,\
        dump — использование результатов предыдущих сканирований.\
        По умолчанию: %(default)s'
        )
    parser.add_argument(
        '-d', '--delay',
        type=float,
        default=1.5,
        help='Задержка между сканированием. По умолчанию: %(default)s'
        )
    parser.add_argument(
        '-S', '--sound',
        action='store_true',
        help='Издавать звук при нахождении цели'
        )
    parser.add_argument(
        '-V', '--vibrate',
        action='store_true',
        help='Вибрировать при нахождении цели'
        )
    parser.add_argument(
        '-T', '--toast',
        action='store_true',
        help='Показывать тост-уведомление при нахождении цели'
        )

    args = parser.parse_args()

    targets = json.load(open('targets.json', 'r', encoding='utf-8'))
    scanner = WiFiScanner(args.interface)
    already_seen = []

    while True:
        if args.mode == 'real':
            results = scanner.scan()
        else:
            results = scanner.scan(dump_only=True)
        if not results:
            continue

        for result in results:
            for target in targets:
                if (result['BSSID'] not in already_seen) and\
                   all(i in result.items() for i in target.items()):
                    already_seen.append(result['BSSID'])

                    # Выводим данные о цели
                    print('Обнаружен роутер Tenda')
                    order = ['BSSID', 'ESSID', 'Level', 'Security type', 'WPS',
                             'WPS locked', 'UUID', 'Manufacturer', 'Model',
                             'Model number', 'Serial number', 'Device name']
                    for key in order:
                        if key not in result:
                            continue
                        print('{}: {}'.format(key, result[key]))
                    print('\n')

                    # Уведомляем пользователя
                    if args.sound:
                        makeSound()
                    if args.toast:
                        makeToast('Обнаружен роутер Tenda\nBSSID: {}\nESSID: {}'.format(
                                  result['BSSID'], result['ESSID']))
                    if args.vibrate:
                        makeVibration()

        time.sleep(args.delay)
