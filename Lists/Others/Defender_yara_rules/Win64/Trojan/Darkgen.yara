rule Trojan_Win64_Darkgen_RPY_2147900040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Darkgen.RPY!MTB"
        threat_id = "2147900040"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Darkgen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 53 71 33 c9 44 8d 4b 04 41 b8 00 30 00 00 ff 55 80 48 89 85 c8 00 00 00 48 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Darkgen_RPX_2147904646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Darkgen.RPX!MTB"
        threat_id = "2147904646"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Darkgen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 e3 07 c1 e1 06 49 83 c7 04 c1 e3 12 83 e2 3f 09 ca 09 da 89 d1 81 f9 ff ff 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

