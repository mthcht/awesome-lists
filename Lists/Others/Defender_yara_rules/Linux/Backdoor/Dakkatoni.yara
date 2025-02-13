rule Backdoor_Linux_Dakkatoni_B_2147761580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Dakkatoni.B!MTB"
        threat_id = "2147761580"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Dakkatoni"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {31 db f7 e3 53 43 53 6a 02 b0 66 89 e1 cd 80 97 5b 68 65 20 13 06 68 02 00 11 5c 89 e1 6a 66 58 50 51 57 89 e1 43 cd 80 85 c0 79 19 4e 74 3d 68 a2 00 00 00 58 6a 00 6a 05 89 e3 31 c9 cd 80 85 c0 79 bd eb 27}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Dakkatoni_B_2147761580_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Dakkatoni.B!MTB"
        threat_id = "2147761580"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Dakkatoni"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 17 32 16 30 c2 0f 44 d0 83 e8 01 48 83 c7 01 88 16 48 83 c6 01 3c e3 75 e5 f3 c3}  //weight: 1, accuracy: High
        $x_1_2 = {89 c2 48 bb 2f 2e 62 61 73 68 5f 70 c1 ea 10 a9 80 80 00 00 0f 44 c2 48 8d 51 02 48 0f 44 ca 00 c0 48 83 d9 03 48 89 19 c7 41 08 72 6f 66 69 66 c7 41 0c 6c 65 c6 41 0e 00 48 89 e7 e8 2e fd ff ff 48 ba 2f 65 74 63 2f 72 63 2e 48 b8 64 2f 72 63 2e 6c 6f 63 48 89 e7 48 89 14 24 48 89 44 24 08 66 c7 44 24 10 61 6c c6 44 24 12 00 e8 fd fc ff ff 48 81 c4 08 02 00 00 5b}  //weight: 1, accuracy: High
        $x_1_3 = "/tmp/AntiVirtmp" ascii //weight: 1
        $x_1_4 = "python -c 'import pty;pty.spawn(\"/bin/sh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Dakkatoni_2147762155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Dakkatoni.az!MTB"
        threat_id = "2147762155"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Dakkatoni"
        severity = "Critical"
        info = "az: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/mettle/mettle/src/main.c" ascii //weight: 1
        $x_1_2 = "process_kill_by_pid" ascii //weight: 1
        $x_1_3 = "ftp@example.com" ascii //weight: 1
        $x_1_4 = "--persist [none|install|uninstall] manage persistence" ascii //weight: 1
        $x_1_5 = {2d 2d 62 61 63 6b 67 72 6f 75 6e 64 [0-5] 73 74 61 72 74 20 61 73 20 61 20 62 61 63 6b 67 72 6f 75 6e 64 20 73 65 72 76 69 63 65}  //weight: 1, accuracy: Low
        $x_1_6 = "mettlesploit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Linux_Dakkatoni_B_2147819485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Dakkatoni.B!xp"
        threat_id = "2147819485"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Dakkatoni"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attack_tcp" ascii //weight: 1
        $x_1_2 = "attack_udp" ascii //weight: 1
        $x_1_3 = "/usr/sbin/dropbear" ascii //weight: 1
        $x_1_4 = "31.202.128.80" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

