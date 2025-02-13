rule TrojanDownloader_AndroidOS_Oldwler_A_2147753603_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/Oldwler.A"
        threat_id = "2147753603"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "Oldwler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "android_id" ascii //weight: 1
        $x_1_2 = {2d e0 6f fd 4e 26 db 0a 2a 7d be 4f f1 f2 41 ed c9 ca 07 ce 0c 92 21 4d af 78 4b 1e d5 26 9f 95 6f 8e a6 a7}  //weight: 1, accuracy: High
        $x_1_3 = {09 20 b4 70 5a c3}  //weight: 1, accuracy: High
        $x_1_4 = {85 55 d8 b9 de 2e 85 21 cd 68 96 53 25 06 e1 0b 39 76 ba a9 0e 24 00 58 bd 37 26 b2 e0 aa c2 b3 3f 4d 43 95 94 c6 25 de b5 63 ba 8b eb 17 b7 16 ae 5c a4 32 12 34 d0 3d 0a 47 d9 98 6b 42 64 61 89 04 17 d7 d6 9e fa d5 5e 7b 71 f0 a5 a3 16 e7}  //weight: 1, accuracy: High
        $x_5_5 = {28 a4 12 22 f6 e1 18 d4 cd f9 c0 2b a6 68 35 e9 0d 41 15 ac 2b 3f b8 e1 38 fe ee 92 82 cf 08 f4 0f 18 9d 9f ef 40 d0 66 52 85 db 37 fb a1 89 ee 48 c9 07 5e 9d 7f 20 76 c7 42 51 df cf 5b 91 83 bd f4 fe 27 98 7c 37 fa fa 9b}  //weight: 5, accuracy: High
        $x_5_6 = "https://lp.cooktracking.com/v1/ls/get" ascii //weight: 5
        $x_5_7 = {21 80 db 03 00 02 21 80 91 04 00 03 91 02 04 03 23 35 71 00 12 00 ?? ?? ?? ?? ?? ?? 04 00 48 06 08 06 48 07 08 02 b7 76 d5 66 ff 00 8d 66 4f 06 05 00 d8 00 00 01 d8 02 02 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 4 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

