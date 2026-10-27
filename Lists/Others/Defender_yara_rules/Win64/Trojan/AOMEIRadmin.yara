rule Trojan_Win64_AOMEIRadmin_DA_2147980997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AOMEIRadmin.DA!MTB"
        threat_id = "2147980997"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AOMEIRadmin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f9 ff 74 ce 42 0f b6 6c 3c 21 44 0f b6 ed 40 84 ed 74 0c 41 83 fd 5c 74 06 41 83 fd 2f 75 d2 42 0f b6 4c 3c 20 83 f9 2f 74 c7 83 f9 5c 74 c2 40 80 fd 5c 74 06 41 83 fd 2f 75 06 42 c6 44 3c 21}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

