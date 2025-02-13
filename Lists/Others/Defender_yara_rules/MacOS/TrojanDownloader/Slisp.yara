rule TrojanDownloader_MacOS_Slisp_A_2147775632_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Slisp.A!MTB"
        threat_id = "2147775632"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Slisp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.tasks.updater" ascii //weight: 2
        $x_1_2 = {53 48 83 ec 28 f2 0f 10 05 7f 06 00 00 e8 4c 04 00 00 48 83 f8 08 49 be 00 00 00 00 00 00 f0 7f 49 bf 00 00 00 00 00 00 7e 40 4d 0f 4c fe f2 0f 10 05 56 06 00 00 e8 23 04 00 00 48 83 f8 08 48 bb 00 00 00 00 00 c0 72 40 49 0f 4c de 48 8b 3d 10 31 00 00 e8 17 04 00 00 48 8b 35 bc 30 00 00 0f 57 c0 0f 29 45 b0 4c 89 7d c0 48 89 5d c8 4c 8b 5d c8 4c 8b 4d c0 4c 8b 55 b0 48 8b 5d b8 ba 0f 80 00 00 b9 02 00 00 00 48 89 c7 41 b8 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {48 83 ec 18 49 89 c6 48 bf 48 65 6c 6c 6f 2c 20 57 48 be 6f 72 6c 64 21 00 00 ed e8 93 06 00 00 0f b6 c9 48 89 c7 48 89 d6 89 ca 4c 89 c1 41 b8 00 00 00 00 41 b9 00 00 00 00 68 00 01 00 00 6a 00 6a 00 6a 00 e8 75 06 00 00 48 83 c4 20 49 89 c5 49 89 d4 89 cb 4d 89 c7 80 e3 01 e8 70 06 00 00 49 89 c2 49 89 d3 0f b6 db 49 b8 00 00 00 00 00 00 f0 7f 4c 89 f0 bf 00 00 00 00 be 01 00 00 00 ba 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MacOS_Slisp_A_2147775632_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Slisp.A!MTB"
        threat_id = "2147775632"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Slisp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.hello.tasker" ascii //weight: 2
        $x_1_2 = {48 81 ec a8 00 00 00 48 89 c3 48 bf 59 6f 75 20 64 69 64 20 48 be 69 74 21 00 00 00 00 eb e8 4e 1b 00 00 0f b6 c9 48 89 c7 48 89 d6 89 ca 4c 89 c1 41 b8 00 00 00 00 41 b9 00 00 00 00 68 00 01 00 00 6a 00 6a 00 6a 00 e8 36 1b 00 00 48 83 c4 20 49 89 c7 49 89 d4 41 89 cd 4d 89 c6 41 80 e5 01 e8 41 1b 00 00 49 89 c2 49 89 d3 45 0f b6 ed 49 b8 00 00 00 00 00 40 8f 40 48 8d 85 40 ff ff ff bf 00 00 00 00 be 01 00 00 00 ba 00 00 00 00 41 b9 00 00 00 00 b9 01 00 00 00 41 56 41 55}  //weight: 1, accuracy: High
        $x_1_3 = {48 8b 5d b8 ba 0f 80 00 00 b9 02 00 00 00 48 89 c7 41 b8 00 00 00 00 41 53 41 51 53 41 52 e8 3f 14 00 00 48 83 c4 20 4c 8b 35 c8 75 00 00 4b 8b 7c 35 00 4b 89 44 35 00 ff 15 a0 28 00 00 4b 8b 7c 35 00 48 85 ff 0f 84 ec 00 00 00 48 8b 35 5b 6d 00 00 e8 0a 14 00 00 4f 8b 64 35 00 4d 85 e4 0f 84 d4 00 00 00 4c 89 e7 ff 15 77 28 00 00 49 89 c7 48 bf 4d 61 69 6e 20 57 69 6e 48 be 64 6f 77 00 00 00 00 eb e8 7d 13 00 00 48 89 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

