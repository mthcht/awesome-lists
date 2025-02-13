rule MonitoringTool_AndroidOS_SpyHasb_A_299910_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SpyHasb.A!MTB"
        threat_id = "299910"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SpyHasb"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KidsLocator1" ascii //weight: 1
        $x_1_2 = "SpyMyHusband1" ascii //weight: 1
        $x_1_3 = "SMS LogaSMS" ascii //weight: 1
        $x_1_4 = "kidstracker.txt" ascii //weight: 1
        $x_1_5 = "PhoneLocatorViewer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_SpyHasb_B_303563_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SpyHasb.B!MTB"
        threat_id = "303563"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SpyHasb"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kidstracker.txt" ascii //weight: 1
        $x_1_2 = "application/car-tracker" ascii //weight: 1
        $x_1_3 = "kidclient2" ascii //weight: 1
        $x_1_4 = "GetListPositions" ascii //weight: 1
        $x_1_5 = "Lcom/company3l/CarTrackerViewer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_SpyHasb_C_358340_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SpyHasb.C!MTB"
        threat_id = "358340"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SpyHasb"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AdicionarURLBuffer" ascii //weight: 1
        $x_1_2 = "okresponse.txt" ascii //weight: 1
        $x_1_3 = "appserver3l.no-ip.biz:8090/ServerGPS" ascii //weight: 1
        $x_1_4 = "KidsLocator" ascii //weight: 1
        $x_1_5 = "com/company3L/FindMyPhone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

