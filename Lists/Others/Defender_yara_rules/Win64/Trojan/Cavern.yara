rule Trojan_Win64_Cavern_GVB_2147974522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cavern.GVB!MTB"
        threat_id = "2147974522"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cavern"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 33 4b 0c 8b 53 12 81 f2 73 00 74 00 48 0b ca 75 51 44 8b 70 08 41 83 fe 02 0f 86 68 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

