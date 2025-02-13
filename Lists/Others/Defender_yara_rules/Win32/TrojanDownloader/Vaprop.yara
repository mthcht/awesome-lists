rule TrojanDownloader_Win32_Vaprop_A_2147634391_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vaprop.A"
        threat_id = "2147634391"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vaprop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://%67%6f%2e%64%68%73%69%74%65" ascii //weight: 1
        $x_1_2 = "http://%67%6F.%64%68%73%69%74%65" ascii //weight: 1
        $x_10_3 = "Nullsoft Install System" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Vaprop_D_2147636888_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vaprop.D"
        threat_id = "2147636888"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vaprop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mbn567PathA" wide //weight: 1
        $x_1_2 = "{1f4de370-ba4f-11d1-d627-00a0c91eedba}" wide //weight: 1
        $x_1_3 = {00 33 36 30 89 68 6b eb 9e f6 dd a4 21 57 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

