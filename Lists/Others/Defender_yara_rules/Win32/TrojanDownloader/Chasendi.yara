rule TrojanDownloader_Win32_Chasendi_A_2147726834_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chasendi.A"
        threat_id = "2147726834"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chasendi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setup_%X.%s" ascii //weight: 1
        $x_1_2 = "/win_setup.dat" ascii //weight: 1
        $x_1_3 = "kaka_url" ascii //weight: 1
        $x_1_4 = "newtab.kaka" ascii //weight: 1
        $x_1_5 = "bits_domains" ascii //weight: 1
        $x_1_6 = "riyah.net;zambi.info;lenda.info;amous.net" ascii //weight: 1
        $x_1_7 = "82.163.143.176;82.163.142.178" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Chasendi_A_2147726834_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chasendi.A"
        threat_id = "2147726834"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chasendi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {23 7d d0 89 c8 c1 e8 03 32 1c 3a ba 19 86 61 18 f7 e2 d1 ea 69 c2 a8 00 00 00 f7 d8 02 9c 01 ?? ?? ?? ?? 88 1e 46 3b 75 d8 0f 82 b6 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 85 14 ff ff ff 8b 55 d4 8d 4a 01 8d 04 c9 89 cf 8d 04 40 8b 84 02 ?? ?? ?? ?? 85 c0 0f 85 77 fe ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {88 1e 46 3b 75 d8 0f 82 c4 ff ff ff e9 69 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {8d 3c 39 8b 5d cc 23 7d d8 2a 14 3b 89 f3 8b 7d d4 29 cb 0f b6 ca 0f b7 8c 09 ?? ?? ?? ?? 01 cb 88 18 40 89 f3 39 f8 0f}  //weight: 1, accuracy: Low
        $x_1_5 = {0f b6 08 89 da 29 c2 0f b7 8c 09 ?? ?? ?? ?? 01 ca 88 10 40 39 f8 0f 82 e4 ff ff ff e9 62 00 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 87 1c 00 00 89 45 e4 0f 85 2b ff ff ff 8b 55 e0 8d 4a 01 8d 04 c9 89 cf 8d 04 40 8b 84 02 ?? ?? ?? ?? 85 c0 0f 85 be fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

