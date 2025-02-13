rule Trojan_Win64_RedLine_RDDM_2147892582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RedLine.RDDM!MTB"
        threat_id = "2147892582"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {45 0f b6 ca 46 0f b6 0c 09 44 30 0c 30 48 ff c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RedLine_ASJ_2147923160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RedLine.ASJ!MTB"
        threat_id = "2147923160"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {43 0f b6 14 11 41 8a c1 83 e0 0f 0f b6 0c 18 32 ca 43 88 0c 11 4d 85 c9 74 07 41 32 cb 43 88 0c 11 44 0f b6 da 49 83 c1 01 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

