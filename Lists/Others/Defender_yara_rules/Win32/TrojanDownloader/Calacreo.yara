rule TrojanDownloader_Win32_Calacreo_A_2147649381_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Calacreo.A"
        threat_id = "2147649381"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Calacreo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "&p=dirupload123&id=" ascii //weight: 1
        $x_1_2 = "&p=bot123&id=" ascii //weight: 1
        $x_1_3 = "&p=cert123&id=" ascii //weight: 1
        $x_1_4 = {6d 6f 64 75 6c 65 73 2f 64 6f 63 73 2f [0-32] 69 6e 64 65 78 31 2e 70 68 70 3f 76 65 72 3d}  //weight: 1, accuracy: Low
        $x_2_5 = {6a 00 6a 1a 68 ?? ?? ?? ?? 6a 00 ff d0 be ?? ?? ?? ?? fc 83 e1 00 8a 06 50 9c 58 25 00 04 00 00 83 f8 00 75 05 83 c6 01 eb 03 83 ee 01 58 3c 00 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Calacreo_C_2147653216_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Calacreo.C"
        threat_id = "2147653216"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Calacreo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "31.214.140.214" wide //weight: 5
        $x_5_2 = "31.31.75.63" wide //weight: 5
        $x_5_3 = "&p=bot" wide //weight: 5
        $x_2_4 = {83 c0 3c 8b 00 03 45 f4 89 45 f0 8b 45 f0 8b 40 78 03 45 f4}  //weight: 2, accuracy: High
        $x_1_5 = "\\Opera\\Opera\\global_history.dat" wide //weight: 1
        $x_1_6 = "C:\\Sandbox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

