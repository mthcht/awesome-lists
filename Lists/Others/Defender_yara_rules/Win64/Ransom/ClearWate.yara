rule Ransom_Win64_ClearWate_YBG_2147961276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/ClearWate.YBG!MTB"
        threat_id = "2147961276"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "ClearWate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ClearWater Ransomware" ascii //weight: 1
        $x_1_2 = "wmic shadowcopy delete" ascii //weight: 1
        $x_1_3 = "README.bmp" ascii //weight: 1
        $x_1_4 = "decryption or recovery" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

