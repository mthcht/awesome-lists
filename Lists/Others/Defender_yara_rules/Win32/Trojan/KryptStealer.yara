rule Trojan_Win32_KryptStealer_AA_2147756359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KryptStealer.AA!MTB"
        threat_id = "2147756359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KryptStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 00 00 80 02 00 c6 45 10 9f c6 45 11 19 c6 45 12 46 c6 45 13 7b c6 45 14 b3 c6 45 15 22 c6 45 16 12 c6 45 17 7f c6 45 18 9f c6 45 19 3b c6 45 1a 08}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 08 83 c0 01 89 45 08 8b 4d 00 83 e9 01 39 4d 08 7f 1b 8b 55 00 83 ea 01 2b 55 08 8b 45 ec 8b 0c d0 f7 d1 8b 55 fc 03 55 08 88 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

