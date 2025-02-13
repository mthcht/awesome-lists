rule Ransom_Win32_Balaclava_AR_2147765496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Balaclava.AR!MTB"
        threat_id = "2147765496"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Balaclava"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "65"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "TotalFiles.txt" ascii //weight: 10
        $x_10_2 = " /c del " ascii //weight: 10
        $x_10_3 = "HOW_TO_RECOVERY_FILES.txt" ascii //weight: 10
        $x_10_4 = "$RECYCLE.BIN" ascii //weight: 10
        $x_10_5 = "ShellExecuteExW" ascii //weight: 10
        $x_10_6 = "ALLUSERSPROFILE" ascii //weight: 10
        $x_1_7 = "Avast" ascii //weight: 1
        $x_1_8 = "Avira" ascii //weight: 1
        $x_1_9 = "COMODO" ascii //weight: 1
        $x_1_10 = "Dr.Web" ascii //weight: 1
        $x_1_11 = "Kaspersky Lab" ascii //weight: 1
        $x_1_12 = "Internet Explorer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

