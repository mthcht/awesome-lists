rule Worm_Win32_Enkye_A_2147685911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Enkye.A"
        threat_id = "2147685911"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Enkye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 00 6e 00 61 00 6b 00 65 00 5f 00 45 00 78 00 70 00 2e 00 65 00 78 00 65 00 00 00 00 00 20 00 00 00 42 00 3a 00 5c 00 53 00 6e 00 61 00 6b 00 65 00 5f 00 45 00 78 00 70 00 2e 00 65 00 78 00 65 00 00 00 00 00 20 00 00 00 43 00 3a 00 5c 00 53 00 6e 00 61 00 6b 00 65 00 5f 00 45 00 78 00 70 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 6e 61 6b 65 45 79 65 73 00 50 72 6f 6a 65 63 74 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

