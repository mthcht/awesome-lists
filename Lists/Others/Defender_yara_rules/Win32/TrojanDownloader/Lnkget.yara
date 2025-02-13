rule TrojanDownloader_Win32_Lnkget_AR_2147691585_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lnkget.AR"
        threat_id = "2147691585"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lnkget"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/update2014.php" ascii //weight: 1
        $x_1_2 = "/ExeFail.php" ascii //weight: 1
        $x_1_3 = {5b 75 10 68 a8 61 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

