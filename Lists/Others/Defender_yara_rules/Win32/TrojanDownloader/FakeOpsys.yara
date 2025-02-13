rule TrojanDownloader_Win32_FakeOpsys_2147624528_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/FakeOpsys"
        threat_id = "2147624528"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeOpsys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Downloading..." ascii //weight: 1
        $x_1_2 = {2d 5e 01 00 00 07 00 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {2d 82 00 00 00 07 00 6a 01 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {68 5e 01 00 00 68 82 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

