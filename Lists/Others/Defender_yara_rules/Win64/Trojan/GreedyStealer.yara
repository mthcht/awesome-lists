rule Trojan_Win64_GreedyStealer_ARA_2147973607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GreedyStealer.ARA!MTB"
        threat_id = "2147973607"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GreedyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 30 0c 03 48 ff c0 44 39 e0 72 f4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GreedyStealer_ARA_2147973607_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GreedyStealer.ARA!MTB"
        threat_id = "2147973607"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GreedyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {4c 39 d1 73 20 41 8a 7c 09 12 31 c7 41 0f af c3 40 88 7c 0c 62 40 b7 01 83 c0 1f 84 c0 0f 44 c7 48 ff c1 eb db}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

