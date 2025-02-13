rule TrojanSpy_AndroidOS_Drinik_C_2147834488_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Drinik.C"
        threat_id = "2147834488"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Drinik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "103 5-94 5-112 5-60 5-69 5-66 5-60 5-68 5-67 5-58 5-60 5-68" ascii //weight: 1
        $x_1_2 = "59 5-101 5-104 5-92 5-100 5-71 5-104 5-103 5-60 5-104 5-103 5-109 5-90 5-92 5-109 5-60 5-90 5-101 5-101 5-108" ascii //weight: 1
        $x_1_3 = "101 5-98 5-103 5-92 5-104 5-101 5-103 5-39 5-90 5-110 5-114 5-39 5-98 5-58 5-108 5-108 5-98 5-108 5-109 5-39 5-115 5-94 5-107 5-104" ascii //weight: 1
        $x_1_4 = "96 5-94 5-109 5-69 5-104 5-96 5-98 5-103 5-96 5-76 5-109 5-90 5-109" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Drinik_AB_2147834960_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Drinik.AB!MTB"
        threat_id = "2147834960"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Drinik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 00 2e 18 70 10 ?? ?? ?? ?? 6e 20 ?? ?? 32 00 0c 02 21 23 36 34 ?? ?? 21 23 12 04 35 34 ?? ?? 46 01 02 04 71 10 ?? ?? 01 00 0a 01 8e 11 6e 20 ?? ?? 10 00 d8 04 04 01 28 f2 6e 10 ?? ?? 00 00 0c 02 11 02 1a 02 00 00 11 02}  //weight: 1, accuracy: Low
        $x_1_2 = {22 04 38 18 70 10 ?? ?? 04 00 21 30 12 01 35 01 11 00 46 02 03 01 71 10 ?? ?? 02 00 0a 02 d8 02 ?? ?? ?? ?? ?? ?? ?? 78 30 32 8e 22 6e 20 ?? ?? 24 00 d8 01 01 01 28 f0 6e 10 ?? ?? 04 00 0c 03 11 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_AndroidOS_Drinik_AA_2147834961_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Drinik.AA!MTB"
        threat_id = "2147834961"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Drinik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1a 00 59 00 6e 20 ?? ?? 04 00 0c 04 22 00 b2 17 70 10 ?? ?? 00 00 21 41 36 13 1a 00 21 43 12 01 35 31 11 00 46 02 04 01 71 10 ?? ?? 02 00 0a 02 d8 02 ?? ?? 8e 22 6e 20 ?? ?? 20 00 d8 01 01 01 28 f0 6e 10 ?? ?? 00 00 0c 03 11 03 1a 03 00 00 11 03}  //weight: 1, accuracy: Low
        $x_1_2 = {1a 00 59 00 6e 20 ?? ?? 03 00 0c 03 22 00 2d 18 70 10 ?? ?? 00 00 21 31 36 14 1a 00 21 34 12 01 35 41 11 00 46 02 03 01 71 10 ?? ?? 02 00 0a 02 d8 02 ?? ?? 8e 22 6e 20 ?? ?? 20 00 d8 01 01 01 28 f0 6e 10 ?? ?? 00 00 0c 03 11 03 1a 03 00 00 11 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

