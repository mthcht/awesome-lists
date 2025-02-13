rule TrojanDownloader_Win32_Emurbo_A_2147602888_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Emurbo.A"
        threat_id = "2147602888"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Emurbo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 00 53 00 42 00 69 00 74 00 73 00 00 00 00 00 ff ff ff ff 04 00 00 00 2e 64 6c 6c 00 00 00 00 55}  //weight: 1, accuracy: High
        $x_1_2 = {2f 63 20 64 65 6c 20 00 20 3e 3e 20 4e 55 4c 00 43 6f 6d 53 70 65 63 00 55}  //weight: 1, accuracy: High
        $x_1_3 = "http://flycodecs.com/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

