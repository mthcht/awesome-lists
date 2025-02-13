rule TrojanDownloader_Win32_Branvine_A_2147803696_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Branvine.A"
        threat_id = "2147803696"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Branvine"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {30 1c 30 40 3b c1 7c f4}  //weight: 3, accuracy: High
        $x_1_2 = {6a 02 55 68 00 ff ff ff 57}  //weight: 1, accuracy: High
        $x_1_3 = {6a 02 57 68 00 ff ff ff 56}  //weight: 1, accuracy: High
        $x_1_4 = {53 56 39 29 00 7c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

