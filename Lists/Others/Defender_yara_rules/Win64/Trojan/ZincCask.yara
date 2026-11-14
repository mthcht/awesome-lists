rule Trojan_Win64_ZincCask_SMW_2147982071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZincCask.SMW!MTB"
        threat_id = "2147982071"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZincCask"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {44 8b 15 ed 5a 0c 00 65 4c 8b 1c 25 58 00 00 00 4f 8b 14 d3 44 0f b6 1c 0a 41 30 c3 45 88 9c 12 7d 00 00 00 04 4d 48 ff c2 83 fa 03 76 d2}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

