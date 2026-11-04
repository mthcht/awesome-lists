rule Trojan_Win64_WardenStealer_BZ_2147981455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WardenStealer.BZ!MTB"
        threat_id = "2147981455"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WardenStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 8b 14 09 4c 33 d0 44 8b 1d d6 d2 08 00 65 48 8b 34 25 58 00 00 00 4e 8b 1c de 4f 89 94 0b 50 00 00 00 49 03 c0 ff c2 49 83 c1 08 83 fa 23 72 cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

