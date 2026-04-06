rule TrojanDownloader_Win64_Dlass_GVD_2147959404_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Dlass.GVD!MTB"
        threat_id = "2147959404"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Dlass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 f4 4a 75 00 c8 b8 71 00 00 a2 0a 00 99 fa 45 ac e8 4b 71 00 00 d4 00 00 c5 c7 db 48}  //weight: 1, accuracy: High
        $x_1_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 36 1b 6f 00 63 86 6b 00 00 ae 0a 00 5b 19 9d 07 38 19 6b 00 00 d4 00 00 02 cb d8 f8}  //weight: 1, accuracy: High
        $x_1_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 0f e7 6e 00 2a 52 6b 00 00 ae 0a 00 23 d3 9d 40 0a e5 6a 00 00 d4 00 00 67 41 e7 a4}  //weight: 1, accuracy: High
        $x_1_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 50 c3 6e 00 6a 2e 6b 00 00 ae 0a 00 6f f7 d8 8f 77 c1 6a 00 00 d4 00 00 fd ec 65 a1}  //weight: 1, accuracy: High
        $x_1_5 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 0d a8 6e 00 27 13 6b 00 00 ae 0a 00 6a 0f f7 47 1f a6 6a 00 00 d4 00 00 cb 7b 3e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

