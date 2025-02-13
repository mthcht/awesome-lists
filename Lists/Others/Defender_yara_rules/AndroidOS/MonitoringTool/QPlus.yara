rule MonitoringTool_AndroidOS_QPlus_A_347827_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/QPlus.A!MTB"
        threat_id = "347827"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "QPlus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e0 05 01 04 b7 53 b0 13 dd 04 04 03 44 04 0f 04 b0 04 b7 43 b1 32 14 03 b9 79 37 9e b1 30 e1 03 02 05 3b 02 03 00 b7 73 e0 04 02 04 b7 43 b0 23 dd 04 00 03 44 04 0f 04 b0 04 b7 43 b1 31}  //weight: 1, accuracy: High
        $x_1_2 = {63 6f 6d 2f 70 6c 75 73 2f [0-16] 2f 61 6b}  //weight: 1, accuracy: Low
        $x_1_3 = "SyncExportFiles" ascii //weight: 1
        $x_1_4 = "QQMessageHistory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

