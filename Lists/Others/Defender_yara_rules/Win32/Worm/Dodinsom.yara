rule Worm_Win32_Dodinsom_A_2147653379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dodinsom.A"
        threat_id = "2147653379"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dodinsom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 2e 00 00 00 04 a4 fe 0a ?? 00 08 00 04 ?? fe fb ef ?? fe f5 73 00 00 00 04 ?? fe 0a ?? 00 08 00 04 ?? fe fb ef ?? fe f5 77 00 00 00 04 ?? fe 0a ?? 00 08 00 04 ?? fe fb ef ?? fe f5 66 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {f4 14 eb 6e ?? ff b3 f4 01 eb ab fb e6 fb ff}  //weight: 1, accuracy: Low
        $x_1_3 = {f5 01 00 00 00 c5 f5 02 00 00 00 c5 f5 04 00 00 00 c5 f5 20 00 00 00 c5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

