rule Trojan_Win64_Marte_KAD_2147902500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Marte.KAD!MTB"
        threat_id = "2147902500"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Marte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ca 0f b7 c0 49 83 c2 ?? c1 e2 ?? 01 d0 01 c1 41 0f b7 42}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Marte_AMBE_2147903243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Marte.AMBE!MTB"
        threat_id = "2147903243"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Marte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 8d 4c 24 ?? ba ?? ?? ?? ?? 41 b8 20 00 00 00 48 8b cb ff 15 ?? ?? ?? ?? 85 c0 74 ?? 48 c7 44 24 28 ?? ?? ?? ?? 45 33 c9 4c 8b c3 c7 44 24 20 ?? ?? ?? ?? 33 d2 33 c9 ff 15 ?? ?? ?? ?? 48 8b c8 ba ?? ?? ?? ?? ff 15}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateThread" ascii //weight: 1
        $x_1_3 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Marte_CCHT_2147903434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Marte.CCHT!MTB"
        threat_id = "2147903434"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Marte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 d0 01 c0 01 d0 29 c1 89 ca 48 63 c2 0f b6 44 05 ?? 44 31 c0 89 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Marte_SPDG_2147928856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Marte.SPDG!MTB"
        threat_id = "2147928856"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Marte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "F4as/kMih7KVLii45mPsIjWl7/18uXL8" ascii //weight: 2
        $x_1_2 = "dZeILtlgC" ascii //weight: 1
        $x_1_3 = "sOreloc4" ascii //weight: 1
        $x_1_4 = "TNNhxyn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

