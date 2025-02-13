rule Virus_Win32_Dervec_A_2147653002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Dervec.A"
        threat_id = "2147653002"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Dervec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {6a 17 68 83 00 00 00 56 ff 15 ?? ?? ?? ?? 89 45 ?? 3b c6 74 75}  //weight: 100, accuracy: Low
        $x_1_2 = {66 c7 04 3e cc cc 66 c7 44 3e 02 cc 60 c6 44 3e 04 68}  //weight: 1, accuracy: High
        $x_1_3 = {83 f8 03 74 1f 83 f8 02 74 1a fe c3 80 fb 47 7e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

