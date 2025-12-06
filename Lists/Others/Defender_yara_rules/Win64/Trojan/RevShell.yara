rule Trojan_Win64_RevShell_NW_2147958943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RevShell.NW!MTB"
        threat_id = "2147958943"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RevShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 45 a0 48 8d 15 d9 36 00 00 48 89 c1 e8 06 18 00 00 48 85 c0 75 30 48 8d 45 a0 48 8d 15 c6 36 00 00 48 89 c1 e8 ee 17 00 00 48 85 c0 75 18 48 8d 45 a0 48 8d 15 b5 36 00 00 48 89 c1 e8 d6 17 00 00 48 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

