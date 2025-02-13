rule Trojan_AndroidOS_Ingopack_A_2147813446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ingopack.A"
        threat_id = "2147813446"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ingopack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "attachBaseContextt" ascii //weight: 1
        $x_1_2 = "La/a/Encryptor" ascii //weight: 1
        $x_2_3 = {12 02 08 00 16 00 71 20 65 00 20 00 0c 01 1a 04 ?? ?? ?? ?? ?? ?? ?? ?? 0c 03 1a 04 ?? ?? ?? ?? ?? ?? 04 00 0c 05 1a 04 ?? ?? 71 10 ?? ?? 04 00 0c 06 1a 04 ?? ?? 71 10 ?? ?? 04 00 0c 07 12 12 23 28 ?? 01 12 02 1c 09 ?? 01 4d 09 08 02 6e 20 ?? ?? 83 00 0c 0a 12 12 23 2b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Ingopack_C_2147814714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ingopack.C!MTB"
        threat_id = "2147814714"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ingopack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "attachBaseContextt" ascii //weight: 1
        $x_1_2 = "La/a/Encryptor" ascii //weight: 1
        $x_1_3 = "javax.crypto.spec.IvParameterSpec" ascii //weight: 1
        $x_2_4 = {12 02 08 00 16 00 71 20 ?? 00 20 00 0c 01 1a 04 ?? ?? ?? ?? ?? ?? ?? ?? 0c 03 1a 04 ?? ?? ?? ?? ?? ?? 04 00 0c 05 1a 04 ?? ?? 71 10 ?? ?? 04 00 0c 06 1a 04 ?? ?? 71 10 ?? ?? 04 00 0c 07 12 12 23 28 ?? 01 12 02 1c 09 ?? 01 4d 09 08 02 6e 20 ?? ?? 83 00 0c 0a 12 12 23 2b}  //weight: 2, accuracy: Low
        $x_2_5 = {12 02 08 00 16 00 71 20 ?? ?? 20 00 0c 01 1a 04 ?? ?? ?? ?? ?? ?? ?? ?? 0c 03 1a 04 ?? ?? ?? ?? ?? ?? 04 00 0c 05 1a 04 ?? ?? 71 10 ?? ?? 04 00 0c 06 1a 04 ?? ?? 71 10 ?? ?? 04 00 0c 07 12 12 23 28 ?? ?? 12 02 1c 09 ?? ?? 4d 09 08 02 6e 20 ?? ?? 83 00 0c 0a 12 12 23 2b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

