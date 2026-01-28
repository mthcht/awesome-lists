rule Ransom_Win64_GEHENNA_YBG_2147961862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/GEHENNA.YBG!MTB"
        threat_id = "2147961862"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "GEHENNA"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Files encrypted:" ascii //weight: 1
        $x_1_2 = "encrypted by" ascii //weight: 1
        $x_1_3 = "README_RESTORE" ascii //weight: 1
        $x_1_4 = "GEHENNA_LOCKER" ascii //weight: 1
        $x_1_5 = "Temp\\svchost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

