rule MonitoringTool_AndroidOS_Cerberus_A_303914_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Cerberus.A!MTB"
        threat_id = "303914"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Cerberus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "START_TRACKING" ascii //weight: 1
        $x_1_2 = "lockNow" ascii //weight: 1
        $x_1_3 = "sendCallLog" ascii //weight: 1
        $x_1_4 = "sendaudiofile.php" ascii //weight: 1
        $x_1_5 = "sendlocation" ascii //weight: 1
        $x_1_6 = "Lcom/lsdroid/cerberus/FakeTrustManager" ascii //weight: 1
        $x_1_7 = "comm/sendpicture.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Cerberus_F_304794_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Cerberus.F!MTB"
        threat_id = "304794"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Cerberus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "preventusbdebug" ascii //weight: 1
        $x_1_2 = "GET_APP_LIST" ascii //weight: 1
        $x_1_3 = "SCREENRECORD" ascii //weight: 1
        $x_1_4 = "cerberus" ascii //weight: 1
        $x_1_5 = "SMS_SENT" ascii //weight: 1
        $x_1_6 = "WIPESD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Cerberus_C_354686_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Cerberus.C!MTB"
        threat_id = "354686"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Cerberus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cerberusapp.com/api/getdevices.php" ascii //weight: 1
        $x_1_2 = "SEND_SMS_RESULT" ascii //weight: 1
        $x_1_3 = "cerberus" ascii //weight: 1
        $x_1_4 = "com/lsdroid/cerberus" ascii //weight: 1
        $x_1_5 = "getdevicestatus.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule MonitoringTool_AndroidOS_Cerberus_E_427185_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Cerberus.E!MTB"
        threat_id = "427185"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Cerberus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendsiminfo" ascii //weight: 1
        $x_5_2 = "CerberusService" ascii //weight: 5
        $x_1_3 = "comm/sendtrack.php" ascii //weight: 1
        $x_1_4 = "START_TRACKING" ascii //weight: 1
        $x_5_5 = "cerberusapp.com/comm/sendpicture.php" ascii //weight: 5
        $x_1_6 = "sendlocation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_AndroidOS_Cerberus_D_432132_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Cerberus.D!MTB"
        threat_id = "432132"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Cerberus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PhoneCallWorker" ascii //weight: 1
        $x_1_2 = "SnapPicService" ascii //weight: 1
        $x_1_3 = "SOSSendWorker" ascii //weight: 1
        $x_1_4 = "com.lsdroid.cerberus.persona" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

