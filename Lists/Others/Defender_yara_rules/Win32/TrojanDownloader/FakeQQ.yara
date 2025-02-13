rule TrojanDownloader_Win32_FakeQQ_A_2147630901_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/FakeQQ.A"
        threat_id = "2147630901"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeQQ"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d e8 8d 45 ec ba 6c e9 4c 00 e8 de 58 f3 ff 8b 55 ec b9 7c e9 4c 00 b8 90 e9 4c 00}  //weight: 1, accuracy: High
        $x_1_2 = {b3 e4 d6 b5 b3 c9 b9 a6 00 00 00 00 b3 e4 d6 b5 b3 c9 b9 a6 c7 eb c9 d4 ba}  //weight: 1, accuracy: High
        $x_1_3 = {53 65 6e 64 20 4f 4b 21 00}  //weight: 1, accuracy: High
        $x_1_4 = {6e 65 74 2f [0-16] 2e 61 73 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

