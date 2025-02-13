rule TrojanDownloader_Win32_Beshe_A_2147600337_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Beshe.A"
        threat_id = "2147600337"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Beshe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 70 6f 6c 69 63 69 65 73 00 00 65 78 70 6c 6f 72 65 72 00 00 00 00 72 75 6e 00 53 68 65 62 65}  //weight: 10, accuracy: High
        $x_10_2 = {45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 00 48 69 64 64 65 6e 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 5c 46 6f 6c 64 65 72 5c 48 69 64 64 65 6e 5c 53 48 4f 57 41 4c 4c 00 00 00 43 68 65 63 6b 65 64 56 61 6c 75 65}  //weight: 10, accuracy: High
        $x_10_3 = {73 68 65 6c 6c 5c 6f 70 65 6e 3d b4 f2 bf aa 28 26 4f 29 00 ff ff ff ff 1b 00 00 00 73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 74 65 73 74 2e 65 78 65}  //weight: 10, accuracy: High
        $x_10_4 = "Open Http://xiazai.196462035.cn/tj.asp" ascii //weight: 10
        $x_1_5 = "autorun.inf" ascii //weight: 1
        $x_1_6 = "Out\\antiautorun" ascii //weight: 1
        $x_1_7 = "Flower.dll" ascii //weight: 1
        $x_1_8 = "config\\systemprofile\\vista.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

