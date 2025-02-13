rule MonitoringTool_AndroidOS_Prospero_A_346065_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Prospero.A!MTB"
        threat_id = "346065"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Prospero"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ResendContacts" ascii //weight: 1
        $x_1_2 = "IncomingSMSBackup" ascii //weight: 1
        $x_1_3 = "KillSMSByID" ascii //weight: 1
        $x_1_4 = "prospero.pro/gps.php" ascii //weight: 1
        $x_1_5 = "KillContacts" ascii //weight: 1
        $x_1_6 = "ProSperoService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

