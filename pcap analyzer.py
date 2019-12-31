import subprocess
import os

def format(a):
    a = a.decode("utf-8")
    a = a.split("\r")
    a = [x for x in a if x != '\n']
    a = [x.split('\n') for x in a]
    a = [[x.strip() for x in y if x.strip()] for y in a]

    return a


def main(pcap_file):
    print()
    print("1. Visited sites")
    print("2. User Agents")
    print("3. Connection details")
    print("4. Grep mode")
    print("5. IP List")
    print("6. Ports Present")
    print("E Exit")
    inp = input("> ")

    try:
        if inp == "1":
            cmd = subprocess.check_output(["tshark", "-r" + pcap_file, "-Tfields", "-edns.qry.name"])
            cmd = format(cmd)
            for a in cmd:
                for x in a:
                    print(x)
            main(pcap_file)
        elif inp == "2":
            cmd = subprocess.check_output(["tshark", "-r" + pcap_file, "-Yhttp.request", "-Tfields", "-ehttp.host", "-ehttp.user_agent"])
            cmd = format(cmd)
            for a in cmd:
                for x in a:
                    print(x)
            main(pcap_file)
        elif inp == "3":
            cmd = subprocess.check_output(["tshark", "-r" + pcap_file, "-Tfields", "-e_ws.col.Protocol", "-etcp.srcport", "-eudp.srcport", "-etcp.dstport", "-eudp.dstport"])
            cmd = format(cmd)
            for a in cmd:
                for x in a:
                    print(x)
            main(pcap_file)
        elif inp == "4":
            inp = input("What do you want to search by >")
            cmd = subprocess.check_output(["tshark", "-r" + pcap_file, "-V"])
            f = open("a.txt", "w+")
            subprocess.call(["tshark", "-ranalyze-me.pcap", "-V"], stderr=subprocess.STDOUT, stdout=f)
            subprocess.call(["grep", "-E", "-w", inp, "a.txt"])
            f.close()
            os.remove("a.txt")
            main(pcap_file)
        elif inp == "5":
            cmd = subprocess.check_output(["tshark", "-r" + pcap_file, "-Tfields", "-eip"])
            cmd = format(cmd)
            for a in cmd:
                for x in a:
                    print(x)
            main(pcap_file)
        elif inp == "6":
            cmd = subprocess.check_output(["tshark", "-r" + pcap_file, "-Tfields", "-etcp.srcport", "-eudp.srcport", "-etcp.dstport", "-eudp.dstport"])
            cmd = format(cmd)
            for a in cmd:
                for x in a:
                    print(x)
            main(pcap_file)
        elif inp == "E" or inp == "e":
            exit()
        else:
            print("That is not a valid input\n")
            main(pcap_file)
    except Exception as e:
        print(e)
        print("Invalid File...\nExiting")

def getFile():
    inp = input("Input pcap file> ")
    return inp

if __name__ == "__main__":
    print("-"*60)
    print("PCAP ANALYZER")
    print("-"*60)
    print()
    
    main(getFile())

