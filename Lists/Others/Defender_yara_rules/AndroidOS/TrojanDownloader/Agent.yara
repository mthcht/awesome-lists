rule TrojanDownloader_AndroidOS_Agent_A_2147793535_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/Agent.A"
        threat_id = "2147793535"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 03 91 00 00 00 14 04 74 50 8c 00 93 04 02 04 14 04 bc 0c 5a 84 23 15 [0-4] 92 06 04 02 b1 06 [0-4] 23 77 [0-4] 26 07 [0-4] 00 00 01 28 12 02 13 09 12 00 35 92 0b 00 13 08 19 00 b3 68 d8 08 08 a9 b0 48 d8 02 02 01 28 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {36 68 0d 00 14 02 59 b9 0d 00 14 04 8c 2e 01 00 92 09 08 06 b0 29 91 04 09 04 33 64 08 00 13 02 33 00 d8 06 04 ec b3 82 b0 26 12 02 12 69 35 92 0f 00 14 08 01 16 0f 00 14 09 5d 07 07 00 92 09 09 06 b3 49 b0 98 d8 02 02 01 28 f1}  //weight: 1, accuracy: High
        $x_1_3 = {35 12 34 00 d8 08 08 a0 48 04 03 02 14 06 9f 32 03 00 b0 86 dc 09 [0-4] 48 09 07 09 14 0a 17 0b 07 00 b3 6a b0 8a 93 0b 0a 0a d8 0b 0b ff b0 4b 92 04 06 08 da 04 04 00 b0 4b b3 88 dc 08 08 01 b0 8b 97 04 0b 09 8d 44 4f 04 05 02 14 04 e3 16 04 00 14 08 5b 6e 0b 00 92 08 08 0a b1 84 b0 64 d8 02 02 01 01 a8 28 cd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_AndroidOS_Agent_C_2147794065_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/Agent.C"
        threat_id = "2147794065"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d5 22 ff 00 b6 32 6e 10 [0-4] 00 01 00 0a 03 22 [0-4] 00 70 10 [0-4] 00 [0-4] 00 13 [0-4] 00 10 23 [0-4] 03 71 20 [0-8] 00 0a [0-4] 6e 40 [0-4] 00 [0-4] 0a [0-4] 12 [0-4] 32 [0-4] 16 00 39 [0-4] 03 00 28 12 b1 [0-4] 12 [0-4] 35 [0-4] 0b 00 48 [0-8] b7 [0-4] 8d [0-4] 4f [0-8] d8 [0-4] 01 28 f6}  //weight: 1, accuracy: Low
        $x_1_2 = {12 12 a5 03 05 02 be 73 a3 02 03 02 9d 02 02 07 bc 25 71 20 [0-4] 65 00 71 20 [0-4] 87 00 71 40 [0-4] 65 87 0a 02 3a 02 03 00 28 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

