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

