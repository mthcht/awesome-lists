rule Trojan_Win64_Minas_GVA_2147971456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Minas.GVA!MTB"
        threat_id = "2147971456"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Minas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8b 15 fa 75 01 00 44 8b cb 41 8b ca 4c 8b c7 4c 33 15 42 88 01 00 83 e1 3f 49 d3 ca 48 8b d6 4d 85 d2 74 0f 48 8b 4c 24 60 49 8b c2 48 89 4c 24 20 eb ae}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

