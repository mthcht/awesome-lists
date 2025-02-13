rule Backdoor_Linux_Tusnami_C_2147788409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tusnami.C!MTB"
        threat_id = "2147788409"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tusnami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "nandemo shiranai wa yo" ascii //weight: 1
        $x_1_2 = "hitteru koto dake" ascii //weight: 1
        $x_1_3 = {41 6c 72 65 61 64 79 [0-2] 6e 69 6e 67 2e}  //weight: 1, accuracy: Low
        $x_1_4 = ":KILL_PORT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Tusnami_B_2147794161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tusnami.B!xp"
        threat_id = "2147794161"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tusnami"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "touch /tmp/gates.lod" ascii //weight: 1
        $x_1_2 = "killall -9 tcpdump" ascii //weight: 1
        $x_1_3 = "killall -9 strace" ascii //weight: 1
        $x_1_4 = "xxx.pokemoninc.com" ascii //weight: 1
        $x_2_5 = "udevd0.pid" ascii //weight: 2
        $x_1_6 = "chmod 755 /etc/persistent/rc.poststart" ascii //weight: 1
        $x_1_7 = "nvram set rc_firewall=\"sleep 120 && wget -qO" ascii //weight: 1
        $x_1_8 = "kill background threads or current packeting" ascii //weight: 1
        $x_1_9 = "connectback shell 2_9062015" ascii //weight: 1
        $x_1_10 = "NOTICE %s :kthr.ssh" ascii //weight: 1
        $x_1_11 = "XMAS <target> <port> <secs> <cwr,ece,urg,ack,psh,rst,fin,syn or null" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Tusnami_D_2147794162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tusnami.D!xp"
        threat_id = "2147794162"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tusnami"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UDP_ATTACK_VECTOR" ascii //weight: 1
        $x_1_2 = "SYN_ATTACK_VECTOR" ascii //weight: 1
        $x_1_3 = "ACK_ATTACK_VECTOR" ascii //weight: 1
        $x_1_4 = "XMS_ATTACK_VECTOR" ascii //weight: 1
        $x_1_5 = "attack has been started" ascii //weight: 1
        $x_1_6 = "botnet" ascii //weight: 1
        $x_1_7 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_8 = "getspoof" ascii //weight: 1
        $x_1_9 = "IRC BOTNET COMMAND" ascii //weight: 1
        $x_1_10 = "flood <host> <dport> <seconds>" ascii //weight: 1
        $x_1_11 = "killer_kill_by_port" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Tusnami_E_2147794163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tusnami.E!xp"
        threat_id = "2147794163"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tusnami"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7c 7c 20 63 64 20 2f 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f 43 68 65 61 74 73 2e 73 68 3b 20 63 68 6d 6f 64 20 37 37 37 20 [0-16] 2e 73 68 3b 20 73 68 20 [0-16] 2e 73 68 3b 20 74 66 74 70}  //weight: 1, accuracy: Low
        $x_1_2 = "HackerScan" ascii //weight: 1
        $x_1_3 = "StartTheLelz" ascii //weight: 1
        $x_1_4 = "sendHTTP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Tusnami_F_2147797456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tusnami.F!xp"
        threat_id = "2147797456"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tusnami"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "unknown <target> <port> <time> <threads> </shit.php" ascii //weight: 1
        $x_1_2 = "grep -v \"lesshts/run.sh\" > %s/.x00%u" ascii //weight: 1
        $x_1_3 = "connectback shell" ascii //weight: 1
        $x_1_4 = "handy downloader" ascii //weight: 1
        $x_1_5 = "Welcome to x00's cback shell" ascii //weight: 1
        $x_1_6 = "mysterious layer7 attack, websites are kill" ascii //weight: 1
        $x_1_7 = "UDP flood" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Tusnami_G_2147797457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Tusnami.G!xp"
        threat_id = "2147797457"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Tusnami"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "unknown <target> <port> <time> <threads> </shit.php" ascii //weight: 1
        $x_1_2 = {77 67 65 74 20 2d 71 4f 20 2d [0-5] 3a 2f 2f 66 6b 64 2e 64 65 72 70 63 69 74 79 2e 72 75 2f 6e 76 72}  //weight: 1, accuracy: Low
        $x_1_3 = "/etc/auto_run_app.sh " ascii //weight: 1
        $x_1_4 = "handy downloader" ascii //weight: 1
        $x_1_5 = "Welcome to x00's cback shell" ascii //weight: 1
        $x_1_6 = "/etc/init.d/S99nvrak" ascii //weight: 1
        $x_1_7 = "/var/run/shit.bkp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

