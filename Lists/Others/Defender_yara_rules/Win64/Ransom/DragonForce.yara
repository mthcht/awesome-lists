rule Ransom_Win64_DragonForce_AB_2147965239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/DragonForce.AB!MTB"
        threat_id = "2147965239"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "DragonForce"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {48 ff c6 48 89 b4 24 a0 07 00 00 48 81 fe 00 01 00 00 74 1c 48 3b b4 24 90 07 00 00 75 e2}  //weight: 6, accuracy: High
        $x_2_2 = ".devman" ascii //weight: 2
        $x_2_3 = "Encryption complete. Files encrypted:" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

