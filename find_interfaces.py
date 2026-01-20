from scapy.all import get_if_list, get_if_addr, conf

print("-" * 60)
print(f"{'Interface Name (Copy this)':<40} | {'IP Address'}")
print("-" * 60)

# Force scapy to reload interface list
conf.iface = conf.iface

for iface in get_if_list():
    try:
        ip = get_if_addr(iface)
        print(f"{iface:<40} | {ip}")
    except:
        print(f"{iface:<40} | Error reading IP")

print("-" * 60)