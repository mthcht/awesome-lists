rule Trojan_Win32_RhadamanthysStealer_EH_2147846341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RhadamanthysStealer.EH!MTB"
        threat_id = "2147846341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RhadamanthysStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8b 44 24 14 03 c5 33 c7 33 c1 2b f0 89 44 24 14 8b c6 c1 e0 04}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

