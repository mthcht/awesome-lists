rule Worm_Win32_DarkSnow_A_2147624965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/DarkSnow.A"
        threat_id = "2147624965"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkSnow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 c2 f8 00 00 00 8b da 83 c3 28 81 3a 62 6c 61 63 75 0e 81 7a 04 6b 69 63 65 75 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

