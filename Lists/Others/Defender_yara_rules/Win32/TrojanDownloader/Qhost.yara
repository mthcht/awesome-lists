rule TrojanDownloader_Win32_Qhost_D_2147679060_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Qhost.D"
        threat_id = "2147679060"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 68 01 03 00 80 6a 00 68 04 00 00 00 68 03 00 00 00 bb a4 06 00 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 08 83 f8 00 b8 00 00 00 00 0f 94 c0 89 45 f8 8b 5d fc 85 db 74 09 53 e8}  //weight: 1, accuracy: High
        $x_1_3 = {5c 48 6f 74 7a 54 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 38 2e 68 74 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {2f 68 6f 73 74 73 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {68 66 7c 00 73 62 7c 00 74 63 63 6b 00}  //weight: 1, accuracy: High
        $x_1_7 = {68 6f 73 74 73 00 7a 74 7c 00}  //weight: 1, accuracy: High
        $x_1_8 = "rhkwo" ascii //weight: 1
        $x_1_9 = {83 c4 04 68 04 00 00 80 6a 00 8b 45 dc 85 c0 75 05 b8}  //weight: 1, accuracy: High
        $x_1_10 = {e9 84 00 00 00 c7 45 e4 00 00 00 00 6a 00 ff 75 e4 e8 63 e8 ff ff 89 45 e0 ff 75 e0 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

