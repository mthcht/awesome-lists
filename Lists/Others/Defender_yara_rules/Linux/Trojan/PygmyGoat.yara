rule Trojan_Linux_PygmyGoat_A_2147927317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/PygmyGoat.A!MTB"
        threat_id = "2147927317"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "PygmyGoat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {45 57 69 dd 92 a0 35 5d 24 92 e7 85 76 39 f8 c2 07 ab 3c 6c 70 34 d1 93 13 ad 06 67 f1 36 da 70 3c b0 bd 03 21 3c 6c 77 9d 17 3e 66 cb 33 ff 75 0f 92 82 15 6d 0e d8 2e db 53 e6 af 8a 92 91 7e e8 88 9c 7e 2f 45 13 11 3f d4 bd 28 d0 f9 7a 81 5b f8 35 db 06 d8 28 4c 79 d8 c0 8d 7e 05 79 f6 2e bc dc be c3 1d 31 2d 9b b0 74 9c 35 79 1b b1 32 85 a5 69 64 46 48 d1 54 ca ee ff a9 75 86 94 0a 13 86 31 cd f4 99 57 c8 6a f8 27 89 14 3f a0 63 63 4d bb cb 8b c8}  //weight: 2, accuracy: High
        $x_2_2 = {40 52 9e 86 be 55 96 ad e0 54 e6 7b 35 71 8d f7 d6 ed ae 2d bd 52 0d 1a 46 48 b0 bb 31 ef b8 46 86 c4 25 43 51 9a 88 13 19 60 a3 b5 29 02 3b 7a d1 c5 d3 5f c8 8b 41 d4 2d 42 c9 38 ce a9 c1 84 e6 8b 26 d3 32 a4 49 9c a8 ff 61 99 79 e1 82 e9 f9 ea c7 c5 51 c1 9d e6 e4 b1 cd f8 61 e5 60 5a f7 79 af 5a a6 e7 9f 78 83 23 f1 98 6c db}  //weight: 2, accuracy: High
        $x_1_3 = "backdoor_dataforward" ascii //weight: 1
        $x_1_4 = "create_backdoor_socket" ascii //weight: 1
        $x_1_5 = "backdoor/server/libs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

