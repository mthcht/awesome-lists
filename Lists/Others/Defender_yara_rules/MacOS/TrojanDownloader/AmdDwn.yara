rule TrojanDownloader_MacOS_AmdDwn_B_2147921854_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/AmdDwn.B!MTB"
        threat_id = "2147921854"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "AmdDwn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 62 1e e8 67 6a b2 e8 3b e8 f2 01 01 67 9e 00 18 61 1e 08 00 d8 d2 08 0b e8 f2 01 01 67 9e 02 10 6e 1e 00 08 41 1f 13 ?? ?? ?? 00 00 80 52 fd 7b 45 a9 f4 4f 44 a9 f6 57 43 a9 ff 83 01 91}  //weight: 2, accuracy: Low
        $x_1_2 = {e8 bf c0 39 e9 0f 40 f9 1f 01 00 71 28 b1 94 9a e8 7f 00 a9 e0 03 13 aa e1 03 13 aa 56 ?? ?? ?? e8 bf c0 39 e8 00 f8 37 20 00 80 52 fd 7b 45 a9 f4 4f 44 a9 f6 57 43 a9 ff 83 01 91}  //weight: 1, accuracy: Low
        $x_1_3 = {e8 01 80 52 e8 1b 00 b9 e8 1b 40 b9 1f 4d 00 71 48 ?? ?? ?? 09 00 00 ?? 29 71 36 91 ca fc ff 10 2b 69 68 38 4a 09 0b 8b 40 01 1f d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MacOS_AmdDwn_A_2147921862_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/AmdDwn.A!MTB"
        threat_id = "2147921862"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "AmdDwn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 40 03 00 00 f2 0f 2a c0 f2 0f 5e 05 cc 03 00 00 f2 0f 59 05 cc 03 00 00 f2 0f 58 05 cc 03 00 00 e8 a7 02 00 00 eb ?? 48 ?? ?? ?? e8 1a 03 00 00 f6 45 c0 01 74 ?? 48 8b 7d d0 e8 e7 02 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 df 48 89 de 31 c9 31 c0 e8 45 02 00 00 f6 45 c0 01 74 ?? 48 8b 7d d0 e8 2a 02 00 00 b8 01 00 00 00 e9 ?? ?? ?? ?? e8 39 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

