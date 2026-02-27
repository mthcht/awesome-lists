rule Ransom_Win64_AiLock_PGAG_2147963877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/AiLock.PGAG!MTB"
        threat_id = "2147963877"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "AiLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".AiLock" ascii //weight: 1
        $x_1_2 = "ReadMe.txt" ascii //weight: 1
        $x_1_3 = ".AiRecovery" ascii //weight: 1
        $x_1_4 = "read=%u Mb/s, write=%u Mb/s, opened=%u, encPS=%u, totalFound=%u, TotalEncrypted=%u" ascii //weight: 1
        $x_1_5 = ".AiLock\\DefaultIcon" ascii //weight: 1
        $x_1_6 = "ShellExecuteW" ascii //weight: 1
        $x_1_7 = "Start Log:%d Network:%d Selfdelete:%d Path=%s" ascii //weight: 1
        $x_1_8 = "Total time of encryption:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

