rule Ransom_Win64_Locker_VD_2147982630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Locker.VD!MTB"
        threat_id = "2147982630"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Locker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "LOCKER" ascii //weight: 2
        $x_2_2 = "RANSOMWARE" ascii //weight: 2
        $x_2_3 = "encrypted" ascii //weight: 2
        $x_1_4 = "devil" ascii //weight: 1
        $x_1_5 = "restore your files" ascii //weight: 1
        $x_1_6 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_7 = "Telegram" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

