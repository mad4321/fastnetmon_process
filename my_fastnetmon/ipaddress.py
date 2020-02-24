__all__ = ['get_subnet']

def get_subnet(ip):
    octets = ip.split('.')
    if len(octets) == 4:
        octets[3] = '0'
        return ('.'.join(octets)) + '/24'
    return ip
