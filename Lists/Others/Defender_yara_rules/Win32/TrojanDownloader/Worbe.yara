rule TrojanDownloader_Win32_Worbe_B_2147601404_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Worbe.B"
        threat_id = "2147601404"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Worbe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {67 00 65 00 74 00 62 00 6f 00 74 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {3f 00 68 00 61 00 73 00 68 00 3d 00 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {67 65 74 62 6f 74 00}  //weight: 2, accuracy: High
        $x_2_4 = {6d 6c 6f 63 61 74 69 6f 6e 00}  //weight: 2, accuracy: High
        $x_2_5 = {5c 00 6d 00 73 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_1_6 = "pizdashka.com" wide //weight: 1
        $x_1_7 = "hujashka.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Worbe_C_2147610082_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Worbe.C"
        threat_id = "2147610082"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Worbe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jqj6j6j#jijmjm" ascii //weight: 1
        $x_2_2 = {53 8a 5c 24 0c 56 8b f0 8d 54 24 14 8b 4a 04 83 c2 04 85 c9 7c 05 32 cb 88 0e 46 4f 85 ff 89 7c 24 14 7f e8}  //weight: 2, accuracy: High
        $x_1_3 = {62 69 6e 32 68 65 78 6e 65 77 2e 70 68 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

