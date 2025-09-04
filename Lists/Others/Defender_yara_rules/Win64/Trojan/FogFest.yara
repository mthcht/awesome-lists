rule Trojan_Win64_FogFest_A_2147951450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FogFest.A!dha"
        threat_id = "2147951450"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FogFest"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8d 5f 08 eb ?? 48 8b 0b 48 8b d6 e8 ?? ?? ?? ?? 85 c0 74 ?? 48 83 c3 10 48 83 3b 00 75 ?? 48 81 c7 08 10 00 00 48 83 3f 00 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

