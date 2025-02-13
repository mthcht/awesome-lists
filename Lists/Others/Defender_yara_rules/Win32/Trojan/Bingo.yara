rule Trojan_Win32_Bingo_RPU_2147830183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bingo.RPU!MTB"
        threat_id = "2147830183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bingo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 8b 55 0c 33 c0 85 d2 74 1a 56 8b 75 10 57 8b 7d 08 8b c8 83 e1 03 8a 0c 31 30 0c 38 40 3b c2 72 f0 5f 5e 33 c0 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bingo_AJ_2147834936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bingo.AJ!MTB"
        threat_id = "2147834936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bingo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a c1 02 c2 30 44 0d f5 41 83 f9 05 73 05 8a 55 f4 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

