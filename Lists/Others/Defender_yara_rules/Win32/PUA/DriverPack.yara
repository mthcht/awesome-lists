rule PUA_Win32_DriverPack_234392_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:Win32/DriverPack"
        threat_id = "234392"
        type = "PUA"
        platform = "Win32: Windows 32-bit platform"
        family = "DriverPack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_3_2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-240] 6d 00 73 00 68 00 74 00 6d 00 6c 00 [0-32] 72 00 75 00 6e 00 68 00 74 00 6d 00 6c 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 3, accuracy: Low
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-240] 64 00 72 00 70 00 2e 00 73 00 75 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

