rule VirTool_WinNT_Jadtre_2147634076_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Jadtre"
        threat_id = "2147634076"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Jadtre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e9 43 25 22 00 0f 84 ?? ?? ?? ?? 83 e9 49 0f 84 ?? ?? ?? ?? 81 e9 d4 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be c0 c1 ca 07 03 d0 41 8a 01 84 c0 75 f1}  //weight: 1, accuracy: High
        $x_1_3 = {81 38 8b ff 55 8b 75 ?? 81 78 01 ff 55 8b ec 75 ?? 83 c0 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_WinNT_Jadtre_C_2147659822_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Jadtre.C"
        threat_id = "2147659822"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Jadtre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 47 00 75 00 6e 00 74 00 69 00 6f 00 72 00 00 00}  //weight: 10, accuracy: High
        $x_5_2 = {ba 55 aa 00 00 66 39 90 fe 01 00 00 75 21 81 b8 a2 01 00 00 11 22 33 44 75 15}  //weight: 5, accuracy: High
        $x_5_3 = {83 ce ff 68 f6 03 00 00 68 f0 01 00 00 e8 ?? ?? ff ff 3c 01 74 22 ff 75 08 68 76 03 00 00 68 70 01 00 00 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

