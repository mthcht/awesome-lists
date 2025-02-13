rule PWS_Win32_Karagany_A_2147806604_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Karagany.A"
        threat_id = "2147806604"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Karagany"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {4d 50 4c 49 42 2e 64 6c 6c 00 45 78 70 6f 72 74 44 61 74 61 00}  //weight: 3, accuracy: High
        $x_1_2 = {88 0c 02 4f 75 ?? c7 45 fc 64 a5 00 00 8b 75 f0 85 f6 7c}  //weight: 1, accuracy: Low
        $x_1_3 = "robert249fsd)af8.?sf2eaya;sd$%85034gsn%@#!afsgsjdg;iawe;otigkbarr" ascii //weight: 1
        $x_1_4 = {33 d2 8a d3 b9 69 00 00 00 2b ca 88 4c 30 ff 46 4f 75}  //weight: 1, accuracy: High
        $x_1_5 = {8b 13 8a 54 32 ff 80 f2 5c 88 54 30 ff 46 4f 75 ?? 8b 03 0f b6 70 02 8b 03 0f b6 78 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

