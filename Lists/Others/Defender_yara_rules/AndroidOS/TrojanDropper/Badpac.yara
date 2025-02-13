rule TrojanDropper_AndroidOS_Badpac_A_2147829880_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Badpac.A!MTB"
        threat_id = "2147829880"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Badpac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {05 1c 20 1c ff f7 f7 fc 29 1c 04 90 20 1c ff f7 f2 fc 3d 49 07 1c 20 1c 79 44 ff f7 75 fc 3b 4a 3b 4b 05 1c 29 1c 7b 44 7a 44 20 1c ff f7 af fc 29 1c 02 1c 20 1c ff f7 b1 fc 36 49 06 1c 20 1c 79 44 ff f7 61 fc 34 4a 34 4b 05 1c 29 1c 7a 44 7b 44 20 1c ff f7 79 fc 00 23 02 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Badpac_B_2147829881_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Badpac.B!MTB"
        threat_id = "2147829881"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Badpac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 49 06 90 28 1c 79 44 ff f7 77 fc 29 68 41 4a 42 4b 06 1c e2 20 40 00 7b 44 0c 58 7a 44 31 1c 28 1c a0 47 31 1c 02 1c 28 1c ff f7 97 fc 3b 49 04 1c 28 1c 79 44 ff f7 60 fc 39 4a 3a 4b 06 1c 7a 44 7b 44 31 1c 28 1c ff f7 68 fc 06 9b 02 1c 31 1c}  //weight: 1, accuracy: High
        $x_1_2 = {47 49 9b 69 79 44 81 46 20 46 98 47 21 68 44 4a 45 4b d1 f8 c4 71 7a 44 7b 44 06 46 20 46 31 46 b8 47 31 46 02 46 20 46 ff f7 cc fc 23 68 3e 49 9b 69 79 44 80 46 20 46 98 47 21 68 3c 4a}  //weight: 1, accuracy: High
        $x_1_3 = {2b 68 49 49 06 90 9b 69 79 44 28 1c 98 47 29 68 47 4a 47 4b 06 1c e2 20 40 00 0c 58 7b 44 31 1c 7a 44 28 1c a0 47 31 1c 02 1c 28 1c ff f7 cd fc 2b 68 40 49 06 1c 9b 69 79 44 28 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

