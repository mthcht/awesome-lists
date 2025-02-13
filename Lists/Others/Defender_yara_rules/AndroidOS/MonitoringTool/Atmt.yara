rule MonitoringTool_AndroidOS_Atmt_A_332686_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Atmt.A!MTB"
        threat_id = "332686"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Atmt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/atmthub/atmtpro/common_model/BackupActivity" ascii //weight: 1
        $x_1_2 = "Lcom/atmthub/atmtpro/receiver_model/sms/SMSreceiver" ascii //weight: 1
        $x_1_3 = "LocationTrackingService" ascii //weight: 1
        $x_1_4 = "PdfFileToSend.pdf" ascii //weight: 1
        $x_1_5 = "listcallString" ascii //weight: 1
        $x_1_6 = "listcalllogString" ascii //weight: 1
        $x_1_7 = "listmesageString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

