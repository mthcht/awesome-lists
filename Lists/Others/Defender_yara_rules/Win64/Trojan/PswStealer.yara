rule Trojan_Win64_PswStealer_2147834739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PswStealer!MTB"
        threat_id = "2147834739"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PswStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 f8 0b 77 27 42 0f b6 4c 10 02 c1 e1 10 42 0f b7 14 10 01 d1 81 c1 00 00 00 07 41 33 0c 00 89 8c 04 00 01 00 00 48 83 c0 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

