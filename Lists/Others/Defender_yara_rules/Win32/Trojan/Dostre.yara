rule Trojan_Win32_Dostre_CA_2147812212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dostre.CA!MTB"
        threat_id = "2147812212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dostre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 33 d2 f7 f3 8a 04 2a 8a 14 31 32 d0 88 14 31 41 3b cf 72 ea}  //weight: 1, accuracy: High
        $x_1_2 = "%s.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

