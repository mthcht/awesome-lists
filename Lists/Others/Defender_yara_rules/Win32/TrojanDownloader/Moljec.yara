rule TrojanDownloader_Win32_Moljec_A_2147720007_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Moljec.A"
        threat_id = "2147720007"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Moljec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)" ascii //weight: 1
        $x_1_2 = "http://api.ipify.org" ascii //weight: 1
        $x_1_3 = {42 4e 00 00 65 78 70 6c 6f 72 65 72 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = {80 34 31 7a 41 3b c8}  //weight: 1, accuracy: High
        $x_1_5 = {8b c1 83 e0 07 8a 04 30 30 04 31 41 3b ca 72 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

