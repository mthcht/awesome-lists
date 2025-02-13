rule Ransom_Win64_Lcry_MK_2147789191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Lcry.MK!MTB"
        threat_id = "2147789191"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Lcry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LCRY_WALL.bmp" ascii //weight: 1
        $x_1_2 = "LCRY RANSOMWARE" ascii //weight: 1
        $x_1_3 = "LCRY_MACHINEID.ID" ascii //weight: 1
        $x_1_4 = "YOU ARE NOW VICTIM OF LCRY RANSOMWARE" ascii //weight: 1
        $x_1_5 = "LCRY_README.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

