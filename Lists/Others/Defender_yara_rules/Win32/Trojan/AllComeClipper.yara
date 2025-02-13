rule Trojan_Win32_AllComeClipper_A_2147916096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AllComeClipper.A!MTB"
        threat_id = "2147916096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AllComeClipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {56 57 8b 3d ?? 50 41 00 0f 1f 80 00 00 00 00 6a 2e ff d3 6a 12 66 8b f0 ff d3 6a 11 66 23 f0 ff d3 66 85 c6 0f ?? ?? 00 00 00 6a 00 6a 02 ff 15 ?? 50 41 00 8b f0 83 fe ff 0f ?? ?? 00 00 00 8d 44 24 38 c7 44 24 38 28 01 00 00 50 56 ff 15 ?? 50 41 00 85 c0 0f 84}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

