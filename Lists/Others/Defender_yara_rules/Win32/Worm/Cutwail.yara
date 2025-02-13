rule Worm_Win32_Cutwail_A_2147600209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Cutwail.A"
        threat_id = "2147600209"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 24 00 07 00 57 ff 15 90 01 04 57 8b d8 ff 15 90 01 04 3b de 75 0b ff 15 90 01 04 83 f8 13 75 0f}  //weight: 3, accuracy: High
        $x_3_2 = {89 45 f0 46 83 fe 1a 0f 82 ?? ff ff ff}  //weight: 3, accuracy: Low
        $x_3_3 = "0bulknet\\FLASH\\" ascii //weight: 3
        $x_2_4 = "Global\\Flash" ascii //weight: 2
        $x_1_5 = "%s\\autorun.inf" ascii //weight: 1
        $x_1_6 = "explorer.exe %s:\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

