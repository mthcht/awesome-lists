rule Trojan_Win64_Phorpiex_NP_2147895928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Phorpiex.NP!MTB"
        threat_id = "2147895928"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f 84 34 02 00 00 48 8b 44 24 ?? 8b 40 70 48 8b 4c 24 ?? 48 03 c8 48 8b c1 48 89 44 24 ?? c7 44 24 50 ?? ?? ?? ?? 48 8b 84 24 28 01 00 00 48 c1 e8 ?? 48 25}  //weight: 5, accuracy: Low
        $x_1_2 = "://185.215.113.84/pp.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Phorpiex_SX_2147950175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Phorpiex.SX!MTB"
        threat_id = "2147950175"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {b8 77 00 00 00 66 89 84 24 2c 08 00 00 b8 69 00 00 00 66 89 84 24 2e 08 00 00 b8 6e 00 00 00 66 89 84 24 30 08 00 00 b8 64 00 00 00 66 89 84 24 32 08 00 00 b8 72 00 00 00 66 89 84 24 34 08 00 00 b8 78 00 00 00 66 89 84 24 36 08 00 00 b8 2e 00 00 00 66 89 84 24 38 08 00 00 b8 74 00 00 00 66 89 84 24 3a 08 00 00 b8 78 00 00 00 66 89 84 24 3c 08 00 00 b8 74 00 00 00}  //weight: 3, accuracy: High
        $x_2_2 = {48 8b 44 24 50 48 8b 00 48 89 44 24 50 48 8b 44 24 50 48 83 78 30 ?? 74 10 48 8b 44 24 48 48 8b 40 10 48 39 44 24 50 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

