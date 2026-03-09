rule Trojan_Win64_Exnet_ARR_2147962785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Exnet.ARR!MTB"
        threat_id = "2147962785"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Exnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_12_1 = {8a 44 24 0c 30 44 0c 0d 41 83 f9}  //weight: 12, accuracy: High
        $x_8_2 = {c6 44 24 5f 00 50 33 c0 0f 9b c0 52 33 d0 c1 e2 ?? 92 5a 0b c1}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Exnet_ARR_2147962785_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Exnet.ARR!MTB"
        threat_id = "2147962785"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Exnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {8b 4c 24 30 8b d0 81 f2 ?? ?? ?? ?? 83 c0 ?? 03 d1 89 54 24 30}  //weight: 11, accuracy: Low
        $x_9_2 = {0f be c9 48 8d 40 ?? 41 33 c8 44 69 c1 ?? ?? ?? ?? 0f b6 08 44 33 c2}  //weight: 9, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

