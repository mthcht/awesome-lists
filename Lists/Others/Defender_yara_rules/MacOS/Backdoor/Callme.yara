rule Backdoor_MacOS_Callme_A_2147815020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Callme.A!xp"
        threat_id = "2147815020"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Callme"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3c 40 67 45 3d 20 ef cd 3d 60 98 ba 3d 40 10 32 3c 00 c3 d2 39 00 00 00 60 42 23 01 61 29 ab 89 61 6b dc fe 61 4a 54 76 91 03 00 04 91 03 00 00 90 43 00 08 91 23 00 0c 91 63 00 10 91 43 00 14 60 00 e1 f0 90 03 00 18}  //weight: 1, accuracy: High
        $x_1_2 = {88 09 00 00 88 4b 00 00 39 6b 00 01 83 7a 70 30 7c 00 12 78 98 09 00 00 39 29 00 01 42 00 ff e4 83 99 70 24 7f 63 db 78 7f bf e2 14 7f a4 eb 78 48 00 2a 51 7c 1f e0 2e 81 5d 00 0c 38 5b 02 04 3b ff 00 10 81 3d 00 04 81 7d 00 08 90 1b 02 04 91 42 00 0c 91 22 00 04 91 62 00 08 7f 9e f8 00 40 9d 00 20 80 19 70 24 80 5a 70 30 39 20 00 10 7d 29 03 a6 39 62 02 04 7d 3f 02 14 4b ff ff 84}  //weight: 1, accuracy: High
        $x_1_3 = {89 3c 00 00 88 0b 02 14 88 4b 02 54 7c 00 4a 78 98 0b 02 14 60 00 00 00 60 00 00 00 60 00 00 00 89 3c 00 00 3b 9c 00 01 7c 42 4a 78 98 4b 02 54 39 6b 00 01 42 00 ff cc 38 00 00 00 38 21 00 b0 90 1f 02 94 80 01 00 08 bb 81 ff f0 7c 08 03 a6 4e 80 00 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

