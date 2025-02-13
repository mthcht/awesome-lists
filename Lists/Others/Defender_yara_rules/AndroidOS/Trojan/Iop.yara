rule Trojan_AndroidOS_Iop_A_2147823858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Iop.A!xp"
        threat_id = "2147823858"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Iop"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getRandomiPKc" ascii //weight: 1
        $x_1_2 = {65 6d 6f 76 65 00 6f 70 65 6e 00 77 72 69 74 65 00 63 6c 6f 73 65 00 4a 4e}  //weight: 1, accuracy: High
        $x_1_3 = {00 5f 5a 31 34 5f 5f 67 6e 75 5f 55 6e 77 69 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Iop_B_2147824586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Iop.B!xp"
        threat_id = "2147824586"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Iop"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 5f 32 50 68 69 50 35 73 74 72 5f 31 00 5f 5a 31 34 5f 5f 67 6e 75 5f 55 6e}  //weight: 1, accuracy: High
        $x_1_2 = {00 12 00 08 00 af 00 00 00 3d 18 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Iop_C_2147824587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Iop.C!xp"
        threat_id = "2147824587"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Iop"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 44 88 03 00 47 88 21 48 80 00 b0 23 67 98 04 00 49 98 08 00 48 90 09 00 4a 90 20 80 99 8f 28 01 b0 af 18 00 b0 27 2c 01 bf af 1c 01 a7 af 20 01 a9 af 24 01 a8 a3 25 01 aa a3 10 00 bc af 1c 01 a4}  //weight: 1, accuracy: High
        $x_1_2 = {34 00 a2 27 38 02 79 8c 18 00 a2 af 09 f8 20 03 21 38 40 00 24 00 bf 8f 08 00 e0 03 28 00 bd 27 09 00 1c 3c 04 89 9c 27 21 e0 99 03 1c 80 83 8f b8 ff bd 27 bc 23 62 24 03 00 49 88 07 00 48 88 0b 00 47 88 0f 00 46 88 13 00 45 88 17 00 44 88 1b 00 4a 88 10 00 bc af 44 00 bf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

