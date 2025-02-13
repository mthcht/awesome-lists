rule TrojanProxy_Win32_Dorando_2147641402_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Dorando"
        threat_id = "2147641402"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorando"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "add rule name=messenger dir=in action=allow protocol=TCP localport=%d" ascii //weight: 1
        $x_1_2 = "portopening TCP %d messenger ENABLE ALL" ascii //weight: 1
        $x_1_3 = "tgkbase.dat" ascii //weight: 1
        $x_1_4 = "twain_32\\usr.dat" ascii //weight: 1
        $x_1_5 = {8b 94 24 18 01 00 00 8b 4c 24 0c 33 c0 8b fe 8b d9 c1 e7 06 03 df 0f be 3c 10 03 f3 2b f8 49 03 f7 40 83 f8 10 7c e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Dorando_B_2147648521_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Dorando.gen!B"
        threat_id = "2147648521"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorando"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 65 73 73 65 6e 67 65 72 00 00 00 47 6c 6f 62 61 6c 5c}  //weight: 1, accuracy: High
        $x_1_2 = "add rule name=messenger dir=in action=allow protocol=TCP localport=%d" ascii //weight: 1
        $x_1_3 = {70 6f 72 74 6f 70 65 6e 69 6e 67 20 54 43 50 20 25 64 20 6d 65 73 73 65 6e 67 65 72 20 45 4e 41 42 4c 45 20 41 4c 4c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

