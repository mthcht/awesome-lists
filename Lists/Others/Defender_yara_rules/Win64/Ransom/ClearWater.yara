rule Ransom_Win64_ClearWater_MKV_2147965709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/ClearWater.MKV!MTB"
        threat_id = "2147965709"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "ClearWater"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CLEARWATER_README.txt" ascii //weight: 2
        $x_2_2 = "Your network has been breached and all data was encrypted" ascii //weight: 2
        $x_1_3 = "ATTENTION!" ascii //weight: 1
        $x_1_4 = "Do not modify, rename or delete files" ascii //weight: 1
        $x_1_5 = "To restore all your PCs and get your network working again" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

