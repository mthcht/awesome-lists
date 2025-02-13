rule Trojan_Win64_Autorun_MP_2147908913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Autorun.MP!MTB"
        threat_id = "2147908913"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 06 83 f8 01 0f 84 4c 01 00 00 85 ff 0f 84 65 01 00 00 48 8b 05 51 27 1c 00 48 8b 00 48 85 c0 74 0c 45 31 c0 ba 02 00 00 00 31 c9}  //weight: 1, accuracy: High
        $x_1_2 = {75 e3 48 8b 35 8c 28 1c 00 31 ff 8b 06 83 f8 01 0f 84 56 01 00 00 8b 06 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Autorun_NA_2147927402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Autorun.NA!MTB"
        threat_id = "2147927402"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f 84 e6 00 00 00 48 8b 05 95 fa 0d 00 48 8d 1c b6 48 c1 e3 03 48 01 d8 48 89 78 ?? c7 00 00 00 00 00 e8 23 0b 00 00 8b 57 ?? 41 b8 30 00 00 00 48 8d 0c 10 48 8b 05 67 fa 0d 00 48 8d 54 24 ?? 48 89 4c 18}  //weight: 3, accuracy: Low
        $x_1_2 = "186.26.107.188" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

