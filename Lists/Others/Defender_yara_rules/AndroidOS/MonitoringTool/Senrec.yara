rule MonitoringTool_AndroidOS_Senrec_A_367657_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Senrec.A!MTB"
        threat_id = "367657"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Senrec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "saveIsRecording" ascii //weight: 1
        $x_1_2 = "com.habra.example.call_recorder" ascii //weight: 1
        $x_1_3 = "/CALL_RECORDS" ascii //weight: 1
        $x_1_4 = "directOfCall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

