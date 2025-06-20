rule Ransom_Win64_RoundeRan_YAE_2147944167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/RoundeRan.YAE!MTB"
        threat_id = "2147944167"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "RoundeRan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Your files are currently encrypted" ascii //weight: 10
        $x_1_2 = "decryptor key" ascii //weight: 1
        $x_1_3 = "result in data loss" ascii //weight: 1
        $x_1_4 = "restore some files for free" ascii //weight: 1
        $x_1_5 = "data to be lost forever" ascii //weight: 1
        $x_1_6 = "data leaks" ascii //weight: 1
        $x_1_7 = "get into the media" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

