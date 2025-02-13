rule TrojanDownloader_Win32_Mariofev_A_2147640628_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mariofev.A"
        threat_id = "2147640628"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mariofev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&x64=" ascii //weight: 1
        $x_1_2 = "&uac=" ascii //weight: 1
        $x_1_3 = {6a 03 ff 75 f8 ff d7 85 c0 74 09 83 3b 0c 73 04}  //weight: 1, accuracy: High
        $x_1_4 = {89 44 24 28 ff 54 24 38 33 f6 bf c8 00 00 00 ff d5 3b 44 24 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Mariofev_B_2147640886_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mariofev.B"
        threat_id = "2147640886"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mariofev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 1b ff 94 93}  //weight: 2, accuracy: High
        $x_2_2 = {53 83 c0 f3 53 50 56 ff 15}  //weight: 2, accuracy: High
        $x_2_3 = "%s?bs=%d&na=%d&uac=%d&id=%s" ascii //weight: 2
        $x_1_4 = "&rid=%d" ascii //weight: 1
        $x_1_5 = "&load=0x%.8X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

