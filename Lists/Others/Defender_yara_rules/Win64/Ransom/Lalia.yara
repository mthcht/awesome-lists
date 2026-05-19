rule Ransom_Win64_Lalia_ALI_2147969704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Lalia.ALI!MTB"
        threat_id = "2147969704"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Lalia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 01 fd 49 8d 0c 1f 48 89 ea 4d 89 e8 e8 ?? ?? ?? ?? 4c 01 eb 48 89 5c 24 38 48 29 de 48 83 fe 09 76 54 48 b8 47 31 32 33 47 41 5a 5a 49 89 04 1f 66 41 c7 44 1f 08 44 52 48 83 c3 0a 48 89 5c 24 38}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

