rule Trojan_WinNT_Almanahe_B_2147595288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Almanahe.B!sys"
        threat_id = "2147595288"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Almanahe"
        severity = "Mid"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 7e 1c 8b 7e 18 32 d2 8b ce ff 15 68 2b 01 00 8b c7 5f 5e c2 08 00 4b 00 65 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70}  //weight: 1, accuracy: High
        $x_1_2 = {00 72 00 69 00 70 00 74 00 6f 00 72 00 54 00 61 00 62 00 6c 00 65 00 00 00 00 00 5c 00 52 00 45 00 47 00 49 00 53 00 54 00 52 00 59 00 5c 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53}  //weight: 1, accuracy: High
        $x_1_3 = {6f 6f 74 5c 73 79 73 74 65 6d 33 32 5c 25 73 00 55 8b ec 81 ec 48 01 00 00 53 56 57 68 44 64 6b}  //weight: 1, accuracy: High
        $x_1_4 = {39 3e 75 54 81 7e 18 73 45 72 76}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_WinNT_Almanahe_A_2147645725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Almanahe.A"
        threat_id = "2147645725"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Almanahe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RioDrvs Usb Driver" wide //weight: 1
        $x_1_2 = "system32\\DRIVERS\\RioDrvs.sys" wide //weight: 1
        $x_1_3 = "E:\\DLMon5\\drv\\obj\\i386\\RioDrvs.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Almanahe_A_2147645725_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Almanahe.A"
        threat_id = "2147645725"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Almanahe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Synaptics Device Driver" wide //weight: 1
        $x_1_2 = "SynTPS.sys" wide //weight: 1
        $x_1_3 = "C111980D-B372-44b4-8095-1B6060E8C647" wide //weight: 1
        $x_1_4 = "E:\\DLMon5\\drivers\\obj\\i386\\SynTPS.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

