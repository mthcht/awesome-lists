rule VirTool_WinNT_Almanahe_A_2147607861_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Almanahe.gen!A"
        threat_id = "2147607861"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Almanahe"
        severity = "Mid"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 75 dc 39 3e 75 54 81 7e 18 73 45 72 76 75 4b c6 45 e7 01 8b f7 89 75 dc 89 5d fc 38 5d e7 74}  //weight: 2, accuracy: High
        $x_1_2 = {89 7d d0 e9 3d ff ff ff c7 45 d8 25 02 00 c0 eb 07}  //weight: 1, accuracy: High
        $x_1_3 = {89 7d fc 74 8b eb 19 3b 7d 1c 75 09 c7 45 30 06 00 00 80 eb 0b 6a 00 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Almanahe_D_2147609345_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Almanahe.D"
        threat_id = "2147609345"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Almanahe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 f9 47 75 2d 80 78 01 45 75 27 80 78 02 54 75 21 80 78 03 20 75 1b 83 65 fc 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 41 57 50 31 83 c7 0c 57 6a 01 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = "E:\\DLMon5\\arp8023\\obj\\i386\\eth8023.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

