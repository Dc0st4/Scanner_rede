import nmap

destino = '192.168.0.*'
porta = '22'

nm = nmap.PortScanner()
nm.scan(hosts=destino, ports=porta)
if nm.all_hosts():
    print('Host encontrado')
    for host in nm.all_hosts():
        host_ip = host
        host_state = nm[host_ip].state()
        port_state = nm[host_ip]['tcp'][int(porta)]['state']
        print(f'{host_ip} - {host_state} - {port_state}')
else:
    print('Host não encontrado')
