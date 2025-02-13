rule TrojanDownloader_Win32_FakeMS_A_2147630055_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/FakeMS.A"
        threat_id = "2147630055"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeMS"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dmmbhnn%oj" ascii //weight: 1
        $x_1_2 = {8b 45 ec 39 45 e4 7d 12 8b 45 e8 03 c1 8b 55 e4 8a 14 32 30 10 ff 45 e4 eb e6 ff 45 e8 eb d9}  //weight: 1, accuracy: High
        $x_1_3 = {73 11 2b 45 f4 33 d2 b9 10 0e 00 00 f7 f1 83 f8 01 eb 12 2b 45 f4 33 d2 b9 80 51 01 00 f7 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

