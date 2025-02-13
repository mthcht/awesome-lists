rule Ransom_MSIL_KillDisk_PAA_2147777647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/KillDisk.PAA!MTB"
        threat_id = "2147777647"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KillDisk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "62"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "killtFile" ascii //weight: 10
        $x_10_2 = "WriteFile" ascii //weight: 10
        $x_10_3 = "KillDisk" ascii //weight: 10
        $x_10_4 = "WipeType" ascii //weight: 10
        $x_10_5 = "WipePass" ascii //weight: 10
        $x_10_6 = "MbrSize" ascii //weight: 10
        $x_1_7 = "GetLogicalDrives" ascii //weight: 1
        $x_1_8 = "get_ProcessName" ascii //weight: 1
        $x_1_9 = "FileSystemInfo" ascii //weight: 1
        $x_1_10 = "get_DriveType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

