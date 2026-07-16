rule Backdoor_MSIL_PangolinEcho_A_2147973455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/PangolinEcho.A!dha"
        threat_id = "2147973455"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PangolinEcho"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Your paramter has a problem. Exception in SleepNow switch case section." wide //weight: 2
        $x_2_2 = "Error happend during Download file from the target system," wide //weight: 2
        $x_1_3 = "get_PipeLineEnabled" ascii //weight: 1
        $x_1_4 = "get_NowDelayTime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

