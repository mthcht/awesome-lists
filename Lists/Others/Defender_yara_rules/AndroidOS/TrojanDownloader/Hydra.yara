rule TrojanDownloader_AndroidOS_Hydra_A_2147744325_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/Hydra.A!MTB"
        threat_id = "2147744325"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "Hydra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 1c 8b 4c 24 1c 0f b6 8c 0b 74 32 ff ff 32 8c 03 61 32 ff ff 88 4c 24 1b 0f b6 44 24 1b 8b 4c 24 1c 88 44 0c 24 ff 44 24 1c 8b 44 24 1c 83 f8 13 72 cb}  //weight: 1, accuracy: High
        $x_1_2 = "libhoter.so" ascii //weight: 1
        $x_1_3 = "_AAssetManager_fromJava" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_AndroidOS_Hydra_B_2147811132_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/Hydra.B"
        threat_id = "2147811132"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "Hydra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_150_1 = {c6 44 73 27 63 aa 16 e5 ba 83 6b b2 a9 14 83 c8 f9 b5 2d 16 b1 bc 19 62 63 87 e2 ba 80 94 4a c6 ff 91 f7 32 af 81 9e 08 bd 22 dd a9 c5 fb d5 bb 93 7a ef ba d5 bd d6 a6 b2 6e 1b 7a 3b 63 86 98 b2 d1 47 3e 53 21 59 bd 49 ea 76 1b 3a 09 11 8f 5f 05 03 03 93 56 92 93 e9 13 21 64 37 59 6b e6 20 92 e6 87 0a 77 e4 fe c6 55 2b 09 61 e9 95 89 bd 06 20 20 2a 5c 7d a2 a3 03 27 be bb 4d 47 40 14 a4 10 5e e6 98 6e 0b 64 7a d9 d5 e5 c6 7d}  //weight: 150, accuracy: High
        $x_150_2 = {e7 72 32 b7 00 41 b8 e1 e1 96 41 53 50 19 72 da 4d 60 7f 3c ef 85 37 37 14 75 56 a5 31 e4 72 dc a5 e1 af 41 6c fa 72 81 74 12 23 da 96 c9 1f ef 65 6c 37 10 31 a6 0f 77 db f4 0f 61 56 5b 92 62 3f e0 1c ed ac cc c8 47 0a 96 a1 c3 bc 26 3c c8 1d ab 8b 8e 55 61 7e 3d 02 03 ab 98 6b f7 a5 ea 91 3f aa 75 40 8f c1 bd bf 72 c0 5a dc 48 3b}  //weight: 150, accuracy: High
        $x_150_3 = {86 20 4c e2 e2 02 0f 6f 41 58 5a 88 3f 28 6f 8c 14 fc ed 7c ef 79 94 24 5c ab 25 6d 65 c9 22 b4 02 0d f1 1f 65 05 fe 58 68 5a 05 7d 4a dd ec 91 b3 67 f4 05 d4 73 ad 4a 59 de f3 9d 2d 5b 4a 08 d4 0c 7f a1 9b 85 6b d3 4e 4f aa 2d f7 8d 30 13 e9 7f ee f5 58 56 0c 4e 83 ad f2 f8 48 09 cb 41 12 03 46 56 f8 25 9e 85 5b 0f ad b0 2d 88 54 af}  //weight: 150, accuracy: High
        $x_30_4 = "libhoter.so" ascii //weight: 30
        $x_30_5 = "libcleanplayer.so" ascii //weight: 30
        $x_30_6 = "libwillslove.so" ascii //weight: 30
        $x_25_7 = "MYDEBUG: Failed to read asset file" ascii //weight: 25
        $x_25_8 = "MYDEBUG: Asset Length: %d" ascii //weight: 25
        $x_25_9 = "MYDEBUG: decodeBitmap filename %s" ascii //weight: 25
        $x_25_10 = "MYDEBUG: got filename %s" ascii //weight: 25
        $x_25_11 = "MYDEBUG: file length %d" ascii //weight: 25
        $x_25_12 = "MYDEBUG: Width %d, Height %d, Stride %d" ascii //weight: 25
        $x_25_13 = "MYDEBUG: res.data() %d" ascii //weight: 25
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_25_*))) or
            ((1 of ($x_30_*) and 3 of ($x_25_*))) or
            ((2 of ($x_30_*) and 2 of ($x_25_*))) or
            ((3 of ($x_30_*) and 1 of ($x_25_*))) or
            ((1 of ($x_150_*))) or
            (all of ($x*))
        )
}

