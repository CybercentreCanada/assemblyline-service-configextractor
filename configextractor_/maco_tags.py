# Documents how Model objects in the MACO standard translate to Assemblyline tags

from typing import Dict, List


def extract_FTP_tags(data: List[Dict]) -> Dict:
    tags = {'network.protocol': ['FTP']}
    for d in data:
        if d.get('password'):
            tags.setdefault('info.password', []).append(d['password'])
        if d.get('hostname'):
            tags.setdefault('network.static.domain', []).append(d['hostname'])
        if d.get('port'):
            tags.setdefault('network.port', []).append(d['hostname'])

        if d.get('path'):
            tags.setdefault('file.path', []).append(d['path'])

    return tags


def extract_SMTP_tags(data: List[Dict]) -> Dict:
    tags = {'network.protocol': ['SMTP']}
    for d in data:
        if d.get('password'):
            tags.setdefault('info.password', []).append(d['password'])
        if d.get('hostname'):
            tags.setdefault('network.static.domain', []).append(d['hostname'])
        if d.get('port'):
            tags.setdefault('network.port', []).append(d['hostname'])

        if d.get('mail_to'):
            tags.setdefault('network.email.address', []).extend(d['mail_to'])
        if d.get('mail_from'):
            tags.setdefault('network.email.address', []).append(d['mail_from'])
        if d.get('subject'):
            tags.setdefault('network.email.subject', []).append(d['mail_from'])

    return tags


def extract_HTTP_tags(data: List[Dict]) -> Dict:
    tags = {}
    for d in data:
        tags.setdefault('network.protocol', []).append(d.get('protocol', 'HTTP').upper())
        if d.get('password'):
            tags.setdefault('info.password', []).append(d['password'])
        if d.get('hostname'):
            tags.setdefault('network.static.domain', []).append(d['hostname'])
        if d.get('port'):
            tags.setdefault('network.port', []).append(d['hostname'])

        if d.get('uri'):
            tags.setdefault('network.static.uri', []).extend(d['uri'])
        if d.get('path'):
            tags.setdefault('network.static.uri_path', []).extend(d['path'])
        if d.get('user_agent'):
            tags.setdefault('network.user_agent', []).append(d['user_agent'])

    return tags


def extract_SSH_tags(data: List[Dict]) -> Dict:
    tags = {'network.protocol': ['SSH']}
    for d in data:
        if d.get('password'):
            tags.setdefault('info.password', []).append(d['password'])
        if d.get('hostname'):
            tags.setdefault('network.static.domain', []).append(d['hostname'])
        if d.get('port'):
            tags.setdefault('network.port', []).append(d['hostname'])

    return tags


def extract_proxy_tags(data: List[Dict]) -> Dict:
    tags = {}
    for d in data:
        if d.get('protocol'):
            tags.setdefault('network.protocol', []).append(d['protocol'])
        if d.get('password'):
            tags.setdefault('info.password', []).append(d['password'])
        if d.get('hostname'):
            tags.setdefault('network.static.domain', []).append(d['hostname'])
        if d.get('port'):
            tags.setdefault('network.port', []).append(d['hostname'])

    return tags


def extract_DNS_tags(data: List[Dict]) -> Dict:
    tags = {}
    for d in data:
        if d.get('ip'):
            tags.setdefault('network.static.ip', []).append(d['ip'])
        if d.get('port'):
            tags.setdefault('network.port', []).append(d['hostname'])

    return tags


def extract_connection_tags(data: List[Dict]) -> Dict:
    tags = {}
    for d in data:
        for side in ['client', 'server']:
            if d.get(f'{side}_ip'):
                tags.setdefault('network.static.ip', []).append(d[f'{side}_ip'])
            if d.get(f'{side}_port'):
                tags.setdefault('network.port', []).append(d[f'{side}_port'])
            if d.get(f'{side}_domain'):
                tags.setdefault('network.static.domain', []).append(d[f'{side}_domain'])

    return tags
