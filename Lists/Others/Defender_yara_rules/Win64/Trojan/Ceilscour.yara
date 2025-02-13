rule Trojan_Win64_Ceilscour_YAA_2147892574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ceilscour.YAA!MTB"
        threat_id = "2147892574"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ceilscour"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 4c 24 68 33 c1 48 8d 0d ?? ?? ?? ?? 48 8b 54 24 60 48 2b d1 48 8b ca 0f b6 c9 81 e1 80 00 00 00 33 c1 48 8b 4c 24 60 88 01 48 63 44 24 20 48 8b 4c 24 60 48 03 c8 48 8b c1 48 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ceilscour_YAB_2147892591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ceilscour.YAB!MTB"
        threat_id = "2147892591"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ceilscour"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 0f b6 07 48 63 ca 41 80 f0 08 48 03 ce 74 56 49 3b ca 73 22 66 66 66 ?? ?? ?? ?? 00 00 00 00 0f b6 c1 40 2a c6 24 08 32 01 41 32 c0 88 01 49 03 cb 49 3b ca 72 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

