rule Trojan_AndroidOS_SpyMax_A_2147817729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyMax.A"
        threat_id = "2147817729"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyMax"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tttrqefvqrevagyqztwwzyq4159" ascii //weight: 1
        $x_1_2 = "xwmgcej4161" ascii //weight: 1
        $x_1_3 = "QdTRIWUx4157" ascii //weight: 1
        $x_1_4 = "ahbzvqbfu4158" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyMax_C_2147950254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyMax.C!MTB"
        threat_id = "2147950254"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyMax"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 40 b2 01 12 02 39 00 03 00 0f 02 1f 04 b2 01 6e 10 5b 08 04 00 0a 00 3d 00 0f 00 d8 00 00 ff 6e 20 5a 08 04 00 0c 03 71 10 92 0d 03 00 0a 03 38 03 f4 ff 0f 01}  //weight: 1, accuracy: High
        $x_1_2 = {54 45 96 07 22 06 76 02 70 40 68 0d 46 10 6e 20 ef 2f 65 00 54 45 96 07 22 06 77 02 70 40 6a 0d 46 10 6e 20 dd 2f 65 00 28 22 54 46 92 07 38 06 15 00 22 05 78 02 70 40 6c 0d 45 10 6e 20 83 0b 56 00 54 45 92 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

