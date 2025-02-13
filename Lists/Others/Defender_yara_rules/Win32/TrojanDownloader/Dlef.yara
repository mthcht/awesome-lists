rule TrojanDownloader_Win32_Dlef_CAG_2147635921_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dlef.CAG"
        threat_id = "2147635921"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dlef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b 40 0c ?? ?? 0c 8b 00}  //weight: 1, accuracy: Low
        $x_1_2 = "kkill /im explorer" ascii //weight: 1
        $x_2_3 = "91.207.6.122" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

