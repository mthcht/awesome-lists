rule Worm_Win32_Ottol_A_2147696941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ottol.A"
        threat_id = "2147696941"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ottol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f5 6e 00 00 00 0b 02 00 04 00 31 00 ff f5 2e 00 00 00 0b 02 00 04 00 31 fc fe f5 69 00 00 00 0b 02 00 04 00 31 f8 fe f5 6e 00 00 00 0b 02 00 04 00 31 f4 fe f5 66 00 00 00 0b 02 00 04 00 31 f0 fe f5 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {23 54 ff f5 62 00 00 00 0b 0a 00 04 00 23 50 ff 2a 23 34 ff f5 61 00 00 00 0b 0a 00 04 00 23 30 ff 2a 23 2c ff f5 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = ".Worm" wide //weight: 1
        $x_1_4 = "hlmrun" wide //weight: 1
        $x_1_5 = "hcurun" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

