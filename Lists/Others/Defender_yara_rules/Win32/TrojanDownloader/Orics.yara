rule TrojanDownloader_Win32_Orics_A_2147640464_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Orics.A"
        threat_id = "2147640464"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Orics"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b c9 3c 69 c9 e8 03 00 00 51 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 53 76 68 73 74 00 00 00 53 77 68 73 74}  //weight: 1, accuracy: High
        $x_1_3 = "POST /bn/listener.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

