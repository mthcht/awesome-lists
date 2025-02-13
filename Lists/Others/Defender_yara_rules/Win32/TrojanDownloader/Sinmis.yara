rule TrojanDownloader_Win32_Sinmis_A_2147637576_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sinmis.A"
        threat_id = "2147637576"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinmis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 57 04 00 00 ff 15 ?? ?? 40 00 68 ?? ?? ?? 00 e8}  //weight: 1, accuracy: Low
        $x_2_2 = {68 20 4e 00 00 ff d5 83 c7 01 83 ff 03 7c b4}  //weight: 2, accuracy: High
        $x_1_3 = "/x/l.php" ascii //weight: 1
        $x_1_4 = "&requestID=" ascii //weight: 1
        $x_1_5 = {3f 69 64 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = {26 6f 73 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

