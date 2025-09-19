rule Trojan_Win32_CryptoStealer_CCJX_2147941666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptoStealer.CCJX!MTB"
        threat_id = "2147941666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {45 78 6f 64 75 73 00 00 4c 65 64 67 65 72 00 00 41 74 6f 6d 69 63 00 00 42 69 74 62 6f 78 00 00 54 72 65 7a 6f 72 00 00 45 6c 65 63 74 72 75 6d 00 00 00 00 43 6f 69 6e 6f 6d 69 00 47 75 61 72 64 61 00 00 4d 6f 6e 65 72 6f 00 00 44 61 65 64 61 6c 75 73 00 00 00 00 57 61 73 61 62 69}  //weight: 5, accuracy: High
        $x_6_2 = {45 78 6f 64 75 73 41 63 74 69 76 65 00 00 00 00 4c 65 64 67 65 72 41 63 74 69 76 65 00 00 00 00 41 74 6f 6d 69 63 41 63 74 69 76 65 00 00 00 00 42 69 74 62 6f 78 41 63 74 69 76 65 00 00 00 00 54 72 65 7a 6f 72 41 63 74 69 76 65 00 00 00 00 45 6c 65 63 74 72 75 6d 41 63 74 69 76 65 00 00 43 6f 69 6e 6f 6d 69 41 63 74 69 76 65}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

