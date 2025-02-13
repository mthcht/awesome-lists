rule Trojan_Win32_XRed_AU_2147848049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XRed.AU!MTB"
        threat_id = "2147848049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XRed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {49 81 f7 67 ad ed 92 d9 f2 92 28 12 40 05 9e c8 48 a2 af b6 6f bb 99 7a cf 76 b9 a4 33 6f df ac c9 41 f8 8e c6 ba a6 6b 06 eb fc 8b e9 0d 9c 18 b9 04 15 97 58 2c 5f fd 32 cc 47 38 13 7d}  //weight: 2, accuracy: High
        $x_2_2 = {84 33 c9 36 29 47 9f 4c 57 35 8f 5b 14 50 23 33 5c 38 01 35 63 69 95 02 11 03 70}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

