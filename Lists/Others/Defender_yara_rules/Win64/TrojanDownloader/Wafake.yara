rule TrojanDownloader_Win64_Wafake_A_2147916712_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Wafake.A"
        threat_id = "2147916712"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Wafake"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8d 74 24 58 b9 01 00 00 00 e8 ?? ?? ?? 00 48 8b d8 e8 fb fe ff ff 45 33 c9 48 89 74 24 20 4c 8b c7 48 8b d3 48 8b 08 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {40 57 48 83 ec 10 48 8d 04 24 48 8b f8 33 c0 b9 01 00 00 00 f3 aa 48 83 c4 10 5f c3 cc cc cc cc 40 57 48 83 ec 10 48 8d 04 24 48 8b f8 33 c0 b9 01 00 00 00 f3 aa 48 83 c4 10 5f c3 cc cc cc cc 40 57 48 83 ec 10 48 8d 04 24 48 8b f8 33 c0 b9 01 00 00 00 f3 aa 48 83 c4 10 5f c3}  //weight: 1, accuracy: High
        $x_1_3 = {4f 00 6c 00 65 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 00 00 4f 00 6c 00 65 00 41 00 75 00 74 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 00 00 00 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 00 00 00 00 53 00 68 00 65 00 6c 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

