rule TrojanDownloader_Win32_Herryday_A_2147624535_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Herryday.A"
        threat_id = "2147624535"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Herryday"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {70 6f 73 74 2e 61 73 70 3f 69 3d [0-6] 26 4d 61 63 3d}  //weight: 5, accuracy: Low
        $x_5_2 = "c:\\windows\\a.txt" ascii //weight: 5
        $x_1_3 = "HARRYBIRTHDAY" wide //weight: 1
        $x_1_4 = "CBT_Struct_for_QQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

