rule TrojanDownloader_Win32_Boaxxe_2147638061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Boaxxe"
        threat_id = "2147638061"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Boaxxe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e8 04 33 c2 25 0f 0f 0f 0f 33 d0 c1 e0 04 33 d8 8b c2 c1 e8 10 33 c3 25 ff ff 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 33 8b 3b 8b ce c1 e9 1d c1 ee 1e 83 e1 01 83 e6 01 c1 ef 1f}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 3a 8b df 81 e3 00 f0 ff ff 81 fb 00 30 00 00 75 0c 8b 5d 08 81 e7 ff 0f 00 00 01 1c 37 8b 78 04 ff 45 fc 83 ef 08 d1 ef 83 c2 02 39 7d fc 72 ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Boaxxe_A_2147639646_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Boaxxe.gen!A"
        threat_id = "2147639646"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Boaxxe"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 74 74 70 3a 2f 2f 25 31 21 64 21 2e 25 32 21 64 21 2e 25 33 21 64 21 2e 25 34 21 64 21 2f 49 4d 47 5f [0-1] 25 35 21 ?? 21 2e 6a 70 67}  //weight: 3, accuracy: Low
        $x_2_2 = "Global\\alazhkvkprmid" ascii //weight: 2
        $x_1_3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Boaxxe_B_2147649916_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Boaxxe.gen!B"
        threat_id = "2147649916"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Boaxxe"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/IMG_0%4!d!.jpg" ascii //weight: 1
        $x_1_2 = {21 64 21 2e 6a 70 67 00 00 00 00 69 00 00 00 77 00 00 00 25 31 21 73 21 25 32 21 73 21 6e 69 6e 65 74 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_2_3 = {3d 25 31 21 64 21 2d 00 0c 00 52 61 6e 67 65 3a 20 62 79 74 65 73}  //weight: 2, accuracy: Low
        $x_2_4 = {3b f0 7e e8 6a 7b 58 66 89 85 00 fe ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

