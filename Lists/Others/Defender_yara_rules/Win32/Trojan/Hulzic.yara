rule Trojan_Win32_Hulzic_2147609974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hulzic"
        threat_id = "2147609974"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hulzic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 3f 4d 75 35 80 7f 01 5a 75 2f 8b 4d fc 33 c0 83 c1 f0 3b cb 76 23 80 3c 07 60 75 18 80 7c 07 01 e8 75 11 80 7c 38 06 61 75 0a 81 7c 38 0c e2 45 cc 63 74 15 40 3b c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

