rule Backdoor_Win32_Swisyn_A_2147691819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Swisyn.A!dha"
        threat_id = "2147691819"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 08 8a 08 32 ca 02 ca 88 08 40 4e 75 f4}  //weight: 1, accuracy: High
        $x_1_2 = {6a 0c 52 8d 44 24 1c 6a 0c 50 68 04 00 00 98 57 c7 44 24 2c 01 00 00 00 c7 44 24 34 e8 03 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 44 24 08 3d 00 00 00 21 74 ?? 3d 00 00 00 23 75 ?? 6a 00 6a 00 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Swisyn_B_2147696499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Swisyn.B!dha"
        threat_id = "2147696499"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Recv %5d bytes from %s:%d" ascii //weight: 1
        $x_1_2 = "[SERVER]connection to %s:%d error" ascii //weight: 1
        $x_1_3 = {21 53 54 4f 50 4b 45 59 4c 4f 47 00}  //weight: 1, accuracy: High
        $x_1_4 = "STOPPORTMAP PortMap End!." ascii //weight: 1
        $x_1_5 = "!PROXYINFO" ascii //weight: 1
        $x_1_6 = {2d 73 6c 61 76 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {2d 74 72 61 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

