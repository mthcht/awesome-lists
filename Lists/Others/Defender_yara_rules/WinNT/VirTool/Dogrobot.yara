rule VirTool_WinNT_Dogrobot_I_2147608068_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Dogrobot.gen!I"
        threat_id = "2147608068"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Dogrobot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 03 2b c7 43 01 e1 c1 e9 02 8b 1d ?? ?? 01 00 8d 45 f0}  //weight: 1, accuracy: Low
        $x_1_2 = {81 38 59 68 e8 03 75 3a 81 78 04 00 00 e8 0e 75 31 8b 45 04 3d 00 00 00 80 72 27 80 38 83 75 22 80 78 01 4d 75 1c 80 78 02 fc 75 16 80 78 03 ff 75 10 80 78 04 6a ff 75 fc e8}  //weight: 1, accuracy: High
        $x_1_3 = {8b 0c b3 0b c9 74 25 8b 79 04 66 8b 07 66 83 f8 03 75 19 8b 47 10 0b c0 74 12 a3 ?? ?? 01 00 89 3d ?? ?? 01 00 33 c0 89 47 10 eb 08 83 c6 01 83 fe 26 72 cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_WinNT_Dogrobot_M_2147609559_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Dogrobot.gen!M"
        threat_id = "2147609559"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Dogrobot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3d 00 00 00 80 72 ?? 80 38 83 75 ?? 8b c0 80 78 01 4d 75}  //weight: 10, accuracy: Low
        $x_10_2 = {25 ff ff fe ff 0f 22 c0 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 0f 84}  //weight: 10, accuracy: Low
        $x_10_3 = "\\Driver\\SafeDog" wide //weight: 10
        $x_10_4 = "\\Device\\Harddisk0" wide //weight: 10
        $x_10_5 = "\\Driver\\ProtectedC" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Dogrobot_J_2147617559_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Dogrobot.gen!J"
        threat_id = "2147617559"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Dogrobot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 e8 8b c6 45 ea 55 c6 45 eb 8b c6 45 ec ec c6 45 f0 e9 0f 85 ?? ?? 00 00 ff 15 ?? ?? ?? ?? 88 45 ff fa 0f 20 c0 25 ff ff fe ff 0f 22 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "ObReferenceObjectByHandle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Dogrobot_K_2147617560_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Dogrobot.gen!K"
        threat_id = "2147617560"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Dogrobot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 6f 49 79 4d 50 33 c0 50 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {77 2f 81 38 8b ff 55 8b 75 1b 81 78 04 ec 56 64 a1 75 12 81 78 08 24 01 00 00 75 09 81 78 0c 8b 75 08 3b 74 07}  //weight: 1, accuracy: High
        $x_1_3 = {51 50 0f 20 c0 89 44 24 04 25 ff ff fe ff 0f 22 c0 58 fa 8b 04 24 a3 ?? ?? ?? ?? 59 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

