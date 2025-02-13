rule PWS_Win32_Prefsap_2147610928_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Prefsap"
        threat_id = "2147610928"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Prefsap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 0d 6a 7c ff 75 dc ff 75 e0 e8 ?? ?? 00 00 6a 0a 6a 5e ff 75 dc ff 75 e0 e8 ?? ?? 00 00 ff 75 e8 ff 75 ec 6a ff ff 75 e0 ff 75 f0 68 ?? ?? 00 10 ff 35 ?? ?? ?? ?? c3 83 f8 01 74 02 eb}  //weight: 2, accuracy: Low
        $x_1_2 = {8a 07 3c 41 72 08 3c 5a 77 04 04 20 eb 0a 3c 61 72 06 3c 7a 77 02 2c 20 88 07 47 49 0b c9 75 e0}  //weight: 1, accuracy: High
        $x_1_3 = {24 3f 3c 3e 73 12 3c 34 73 0a 04 41 3c 5b 72 0f 04 06 eb 0b 04 fc eb 07 2c 3e c0 e0 02 04 2b 05 00 c1 c2 06}  //weight: 1, accuracy: Low
        $x_1_4 = {b1 07 8b c6 24 0f 3c 0a 1c 69 2f 88 04 11 c1 ee 04 49 79 ee}  //weight: 1, accuracy: High
        $x_2_5 = {89 45 f8 c7 00 53 53 49 44 68}  //weight: 2, accuracy: High
        $x_1_6 = "robert249fsd)af8.?sf2eaya;sd$%85034gsn%@#!afsgsjdg;iawe;otigkbarr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

