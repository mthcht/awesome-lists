rule TrojanDownloader_Linux_Hajime_A_2147794758_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/Hajime.A!xp"
        threat_id = "2147794758"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "Hajime"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 00 a0 e3 01 10 a0 e3 06 20 a0 e3 07 00 2d e9 01 00 a0 e3 0d 10 a0 e1 66 00 90 ef 0c d0 8d e2 00 60 a0 e1 70 10 8f e2 10 20 a0 e3 07 00 2d e9 03 00 a0 e3 0d 10 a0 e1 66 00 90 ef 14 d0 8d e2 4f 4f 4d e2 05 50 45 e0}  //weight: 1, accuracy: High
        $x_1_2 = {06 00 a0 e1 04 10 a0 e1 4b 2f a0 e3 01 3c a0 e3 0f 00 2d e9 0a 00 a0 e3 0d 10 a0 e1 66 00 90 ef 10 d0 8d e2 00 50 85 e0 00 00 50 e3 04 00 00 da 00 20 a0 e1 01 00 a0 e3 04 10 a0 e1 04 00 90 ef ee ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {8f a4 ff d4 27 a5 ff d0 24 02 0f a4 01 01 01 0c 8f a4 ff ff 27 a5 ff d0 28 06 00 ff 24 02 0f a3 01 01 01 0c 18 40 00 03 00 00 00 00 10 e0 ff f4 00 00 00 00 24 04 00 00 24 02 0f a1 01 09 09 0c}  //weight: 1, accuracy: High
        $x_1_4 = {24 02 10 57 01 01 01 0c af a2 ff ff 8f a4 ff ff 04 d0 ff ff 00 00 00 00 27 e5 00 58 24 0c ff ef 01 80 30 27 24 02 10 4a 01 01 01 0c 28 06 ff ff}  //weight: 1, accuracy: High
        $x_1_5 = {d4 ff a4 8f d0 ff a5 27 a4 0f 02 24 0c 01 01 01 ff ff a4 8f d0 ff a5 27 ff 00 06 28 a3 0f 02 24 0c 01 01 01 03 00 40 18 00 00 00 00 f4 ff e0 10 00 00 00 00 00 00 04 24 a1 0f 02 24 0c 09 09 01}  //weight: 1, accuracy: High
        $x_1_6 = {ff ff 06 28 57 10 02 24 0c 01 01 01 ff ff a2 af ff ff a4 8f ff ff d0 04 00 00 00 00 58 00 e5 27 ef ff 0c 24 27 30 80 01 4a 10 02 24 0c 01 01 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

