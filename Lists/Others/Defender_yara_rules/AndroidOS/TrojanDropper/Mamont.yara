rule TrojanDropper_AndroidOS_Mamont_A_2147959451_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Mamont.A!MTB"
        threat_id = "2147959451"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 0a 6e 10 4b 0c 00 00 0a 0d 82 dd c9 da 82 9d 6e 10 0a 0c 00 00 0a 0e 82 ee c9 ed 71 10 ad 02 0b 00 0a 0e 2d 0e 0e 06 15 0f 80 3f 38 0e 15 00 7f dd 71 30 7e 02 db 0a 0a 0a}  //weight: 1, accuracy: High
        $x_1_2 = {08 13 0f 00 74 08 ae 1b 13 00 52 03 6f 06 44 09 0a 08 b1 93 59 03 6f 06 52 03 7d 06 b0 93 59 03 7d 06 38 0e 5b 00 44 03 1a 08 b1 36 b0 67 3b 07 21 00 7b 63 82 33 6e 10 0a 0c 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {54 79 40 0b 38 09 0a 00 32 46 08 00 6e 10 67 1b 09 00 0a 09 90 22 09 22 02 09 22 00 38 24 08 00 32 46 06 00 32 b6 04 00 13 1e 05 00 08 22 04 00 54 74 40 0b 38 04 30 00 33 b6 0f 00 02 25 08 00 54 78 43 0b 54 44 43 0b 02 26 0c 00 12 6c 6e 5c de 17 81 94 28 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_AndroidOS_Mamont_B_2147959452_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Mamont.B!MTB"
        threat_id = "2147959452"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b0 42 b2 82 e2 02 02 08 6e 20 51 09 27 00 55 02 4d 02 12 04 01 25 07 32 54 03 4f 02 38 05 8f 00 6e 10 4c 03 00 00 0a 05 12 09 15 0a 00 40 38 05 08 00 6e 10 46 09 07 00 0a 05 c9 a5 28 02}  //weight: 1, accuracy: High
        $x_1_2 = {82 99 c7 95 87 55 6e 10 9d 09 04 00 0a 09 6e 10 d1 09 00 00 0c 0a 6e 10 8c 09 0a 00 0a 0a 82 aa c7 a9 87 99 3a 05 56 00 3a 09 54 00 6e 10 a7 09 04 00 0a 0a 87 aa 54 0b 49 02 52 bb 1b 02 da 0b 0b 02 b0 ab b0 5b}  //weight: 1, accuracy: High
        $x_1_3 = {b1 cb b1 5b 82 b5 6e 10 d1 09 00 00 0c 0b 52 bb ea 04 54 0c 49 02 52 cc 1b 02 b1 cb b1 9b 82 b9 7f 5b 7f 9c 6e 30 19 09 ba 0c 6e 20 47 03 a0 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

