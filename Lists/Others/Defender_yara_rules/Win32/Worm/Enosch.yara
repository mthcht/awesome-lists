rule Worm_Win32_Enosch_A_2147681154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Enosch.A"
        threat_id = "2147681154"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Enosch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6c 65 63 74 75 72 65 20 6e 6f 74 65 73 2e 65 78 65 00 00 00 65 73 73 61 79 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_1_2 = {65 6e 6f 75 67 68 73 63 68 6f 6f 6c 40 67 6d 61 69 6c 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 61 6d 61 6d 6d 6d 61 6d 61 6d 61 6d 40 79 61 68 6f 6f 2e 63 6f 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

