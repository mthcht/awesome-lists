rule Trojan_MSIL_Xworm_NEAA_2147844429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xworm.NEAA!MTB"
        threat_id = "2147844429"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$82ff5e55-94f0-4530-b928-7deaba1cdf37" ascii //weight: 5
        $x_1_2 = "get_HardwareLock_BIOS" ascii //weight: 1
        $x_1_3 = "GetProcessesByName" ascii //weight: 1
        $x_1_4 = "IntelliLock.Licensing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xworm_NEAB_2147844543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xworm.NEAB!MTB"
        threat_id = "2147844543"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 11 01 28 0d 00 00 06 13 03 38 18 00 00 00 28 ?? 00 00 0a 11 00 28 13 00 00 06 28 ?? 00 00 0a 13 01}  //weight: 10, accuracy: Low
        $x_1_2 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_3 = "secondopen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xworm_KAD_2147905524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xworm.KAD!MTB"
        threat_id = "2147905524"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "nc.bmexcellentfocus" ascii //weight: 2
        $x_2_2 = "SecurityHealth.bin" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xworm_KAE_2147910953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xworm.KAE!MTB"
        threat_id = "2147910953"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5f 63 13 04 08 11 04 60 d2 0c 07 11 05 25 20 01 00 00 00 58 13 05 08 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xworm_KAG_2147917156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xworm.KAG!MTB"
        threat_id = "2147917156"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {9a 0d 00 07 08 8f ?? 00 00 01 25 71 ?? 00 00 01 09 08 09 8e 69 5d 91 61 d2 81 ?? 00 00 01 00 11 07 17 58 13 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xworm_SWJ_2147925453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xworm.SWJ!MTB"
        threat_id = "2147925453"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 20 00 40 00 00 6a 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 59 28 ?? 00 00 0a 69 13 06 06 11 04 16 11 06 6f ?? 00 00 0a 13 07 16 13 08 38 29 00 00 00 00 11 04 11 08 11 04 11 08 91 7e 11 00 00 04 11 05 91 61 08 11 05 91 61 d2 9c 11 05 17 58 09 5d 13 05 00 11 08 17 58 13 08 11 08 11 07 fe 04 13 09 11 09 3a c8 ff ff ff 07 11 04 16 11 07 6f ?? 00 00 0a 00 00 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a fe 04 13 0a 11 0a 3a 73 ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xworm_YAC_2147933902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xworm.YAC!MTB"
        threat_id = "2147933902"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {09 59 08 1f 0a 5d 59 20 00 01 00 00 58 20 00 01 00 00 5d d1 13 04 07}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xworm_SWB_2147937546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xworm.SWB!MTB"
        threat_id = "2147937546"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d0 49 00 00 01 28 ?? 00 00 0a 72 da 01 00 70 18 8d 1f 00 00 01 25 16 d0 17 00 00 01 28 ?? 00 00 0a a2 25 17 d0 1f 00 00 01 28 ?? 00 00 0a a2 28 ?? 00 00 0a 14 18 8d 07 00 00 01 25 16 02 8c 17 00 00 01 a2 25 17 03 a2 6f ?? 00 00 0a 74 42 00 00 01 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xworm_SWC_2147937547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xworm.SWC!MTB"
        threat_id = "2147937547"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1f 10 8d 0e 00 00 01 13 07 09 28 ?? 00 00 0a 16 11 07 16 1a 28 ?? 00 00 0a 11 04 28 ?? 00 00 0a 16 11 07 1a 1a 28 ?? 00 00 0a 11 05 28 ?? 00 00 0a 16 11 07 1e 1a 28 ?? 00 00 0a 11 06 28 ?? 00 00 0a 16 11 07 1f 0c 1a 28 ?? 00 00 0a 11 07 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

