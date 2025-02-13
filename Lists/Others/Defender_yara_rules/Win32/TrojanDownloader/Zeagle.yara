rule TrojanDownloader_Win32_Zeagle_A_2147629153_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zeagle.A"
        threat_id = "2147629153"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zeagle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "705773407340706C6EE2CA1518C45E3618A8" ascii //weight: 1
        $x_1_2 = "88999181918178E9909BB96CD1C8A0303522FF65" ascii //weight: 1
        $x_1_3 = "://goo.gl/" ascii //weight: 1
        $x_1_4 = {ff 68 00 80 00 00 6a 00 8b 45 fc 50 ff 15 13 00 53 56 6a ?? 8b 45 f8 e8 ?? ?? ?? ff 50 ff d7 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

