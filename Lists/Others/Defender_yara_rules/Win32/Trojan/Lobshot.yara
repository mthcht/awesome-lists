rule Trojan_Win32_Lobshot_ALB_2147963128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lobshot.ALB!MTB"
        threat_id = "2147963128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lobshot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 57 c7 44 24 14 57 54 53 45 c7 44 24 18 6e 75 6d 65 c7 44 24 1c 72 61 74 65 c7 44 24 20 53 65 73 73 c7 44 24 24 69 6f 6e 73 c7 44 24 28 41 00 00 00 ff d6 8d 44 24 0c c7 44 24 0c 57 54 53 51 50 57 c7 44 24 18 75 65 72 79 c7 44 24 1c 55 73 65 72 c7 44 24 20 54 6f 6b 65 c7 44 24 24 6e 00 00 00 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

