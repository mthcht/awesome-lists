rule Ransom_Win64_AidLocker_YAN_2147929985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/AidLocker.YAN!MTB"
        threat_id = "2147929985"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "AidLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Hello, AidLocker is here" ascii //weight: 10
        $x_1_2 = "downloaded your data" ascii //weight: 1
        $x_1_3 = "encrypted your files" ascii //weight: 1
        $x_1_4 = "deleted backups" ascii //weight: 1
        $x_1_5 = "restore your infrastructure" ascii //weight: 1
        $x_1_6 = "publication of your data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

