rule VirTool_WinNT_Lamechi_A_2147626695_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Lamechi.A"
        threat_id = "2147626695"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Lamechi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 14 80 f9 e9 75 0f 80 fa 2b 75 0a 80 bc 05 ?? ?? ?? ff e1 74 08}  //weight: 1, accuracy: Low
        $x_1_2 = {81 45 08 47 86 c8 61 03 f9 33 c7 2b d0 ff 4d 0c 75 be}  //weight: 1, accuracy: High
        $x_1_3 = {8d 7d f0 ab ab ab 68 48 02 00 00 ab}  //weight: 1, accuracy: High
        $x_1_4 = {80 3c 37 e8 75 17 8b 44 37 01 03 c7 8d 5c 30 05 53 ff 15 ?? ?? ?? ?? 84 c0 75 08 33 db 47 83 ff 40 72 dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

