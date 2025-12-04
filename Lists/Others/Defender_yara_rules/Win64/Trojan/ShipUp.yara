rule Trojan_Win64_ShipUp_GVA_2147958836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShipUp.GVA!MTB"
        threat_id = "2147958836"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShipUp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {44 88 64 24 74 45 0f b6 3c 37 41 bc 87 00 00 00 49 81 f4 af 00 00 00 45 01 fd 49 83 fc 30 0f 83 82 0f 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {41 0f b6 34 34 88 54 24 50 44 88 44 24 51 40 88 7c 24 52}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

