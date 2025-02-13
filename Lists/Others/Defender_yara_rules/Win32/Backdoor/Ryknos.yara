rule Backdoor_Win32_Ryknos_A_2147574093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ryknos.gen!A"
        threat_id = "2147574093"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryknos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 74 24 10 8b 5c 24 14 89 f1 83 c8 ff 40 80 3c 01 00 75 f9 89 c7 eb 09 0f be 04 3e 31 d8 88 04 3e}  //weight: 5, accuracy: High
        $x_1_2 = {ff ff 68 04 37 00 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = {09 c0 75 13 68 3a 03 00 00 e8}  //weight: 1, accuracy: High
        $x_1_4 = {0f b6 16 46 80 fa 61 72 08 80 fa 7a 77 03 80 ea 20}  //weight: 1, accuracy: High
        $x_1_5 = {ff ff 83 c4 24 31 db eb 12 6a 15 ff 34}  //weight: 1, accuracy: High
        $x_1_6 = {00 00 99 f7 fb 8b 3c}  //weight: 1, accuracy: High
        $x_1_7 = "if exist \"\"C:\\myapp.exe\"\" goto" ascii //weight: 1
        $x_1_8 = "netsh firewall set" ascii //weight: 1
        $x_1_9 = "del \"C:\\TEMP\\" ascii //weight: 1
        $x_1_10 = "%s\\ed%s.%s" ascii //weight: 1
        $x_1_11 = "PRIVMSG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Ryknos_B_2147574964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ryknos.gen!B"
        threat_id = "2147574964"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryknos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {eb 09 0f be 04 3e 31 d8 88 04 3e 89 f8 48 89 c7 7d}  //weight: 3, accuracy: High
        $x_2_2 = "if exist \"C:\\myapp.exe\" goto" ascii //weight: 2
        $x_1_3 = {2c 67 7a 67 00}  //weight: 1, accuracy: High
        $x_1_4 = "%s \"%s\" %s " ascii //weight: 1
        $x_2_5 = "netsh firewall set allowedprogram" ascii //weight: 2
        $x_1_6 = ":uptime" ascii //weight: 1
        $x_1_7 = ":delete" ascii //weight: 1
        $x_1_8 = ":execute" ascii //weight: 1
        $x_1_9 = {31 39 32 2e 31 36 38 00}  //weight: 1, accuracy: High
        $x_1_10 = "PRIVMSG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

