rule TrojanDropper_Win32_Babar_A_2147691873_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Babar.A!dha"
        threat_id = "2147691873"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 00 ff ff ff 81 f9 00 16 45 bf 74 ?? 8b 55 f0 52 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 cf 08 be 00 ff 00 ff 23 fe c1 c0 08 ba ff 00 ff 00 23 c2 0b f8}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4e 0c 8b 56 10 8a 0c 11 8a 04 3b 32 c8 88 0f 8b 4e 0c 8b 56 10 88 04 11 ff 46 0c}  //weight: 1, accuracy: High
        $x_1_4 = "Babar64\\Babar64\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_Win32_Babar_ARA_2147892683_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Babar.ARA!MTB"
        threat_id = "2147892683"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 f7 89 f0 31 db 83 c7 ?? 81 2e ?? ?? ?? ?? 83 c6 04 66 ba 5d e9 39 fe 7c ef}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

