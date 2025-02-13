rule Trojan_Win32_Runwaprep_A_2147716534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Runwaprep.A"
        threat_id = "2147716534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Runwaprep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0d 00 50 00 57 00 4c 00 43 00 52 00 52 00}  //weight: 2, accuracy: High
        $x_2_2 = {4c 4d 02 57 50 4e 51 03 00}  //weight: 2, accuracy: High
        $x_2_3 = {07 51 04 4a 4d 51 56 7d 4b 46 1f 07 46 04 46 47 4e 43 5b 1f 07 46 00}  //weight: 2, accuracy: High
        $x_1_4 = {8a 14 06 80 f2 4d ff 45 d0 88 14 01 40 83 f8 1e 7c}  //weight: 1, accuracy: High
        $x_1_5 = {8b ca 66 8b 14 10 66 83 f2 22 66 89 14 08 83 c0 02 43 83 f8 14 7c}  //weight: 1, accuracy: High
        $x_1_6 = {8b ce 8a 14 06 80 f2 23 ff 45 d0 88 14 01 40 83 f8 14 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

