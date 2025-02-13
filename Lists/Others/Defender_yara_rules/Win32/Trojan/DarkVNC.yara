rule Trojan_Win32_DarkVNC_RPY_2147850294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkVNC.RPY!MTB"
        threat_id = "2147850294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkVNC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c0 e0 04 2c 10 0a c3 32 c1 32 44 24 10 88 06 32 f8 83 c6 02 83 c5 02 eb 0d 8d 48 ff bf 01 00 00 00 c0 e1 04 0a cb 8a 02 84 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

