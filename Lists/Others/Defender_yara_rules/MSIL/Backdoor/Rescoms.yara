rule Backdoor_MSIL_Rescoms_AA_2147733549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Rescoms.AA!bit"
        threat_id = "2147733549"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rescoms"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SpawnNewProcess" ascii //weight: 1
        $x_1_2 = "SetHidden" ascii //weight: 1
        $x_1_3 = "DownExec" ascii //weight: 1
        $x_1_4 = "DetectVm" ascii //weight: 1
        $x_1_5 = "MonitoringSelf" ascii //weight: 1
        $x_1_6 = "RunPersistence" ascii //weight: 1
        $x_1_7 = "ReclaimMutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_MSIL_Rescoms_C_2147794425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Rescoms.C!MTB"
        threat_id = "2147794425"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rescoms"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 13 0d 11 0c 13 0e 11 0d 11 0e 11 0d 11 0e 6f ?? 00 00 0a 08 11 0c 17 59 6f ?? 00 00 0a 58 6f ?? 00 00 0a 00 00 11 0c 17 58 13 0c 11 0c 08 6f ?? 00 00 0a fe 04 13 0f 11 0f 2d c3}  //weight: 10, accuracy: Low
        $x_3_2 = "Cyotek" ascii //weight: 3
        $x_3_3 = "txtbxtab" ascii //weight: 3
        $x_3_4 = "TextBoxTabStops" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

