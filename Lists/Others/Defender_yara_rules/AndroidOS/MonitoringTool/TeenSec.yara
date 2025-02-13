rule MonitoringTool_AndroidOS_TeenSec_B_358157_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/TeenSec.B!MTB"
        threat_id = "358157"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "TeenSec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "saveKeystrokeData" ascii //weight: 1
        $x_1_2 = "BrowserContentObserver" ascii //weight: 1
        $x_1_3 = "calllog.dat" ascii //weight: 1
        $x_1_4 = "saveIncommingPhoneNumber" ascii //weight: 1
        $x_1_5 = "bookmarklog.dat" ascii //weight: 1
        $x_1_6 = "EmailMediaRecorder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_TeenSec_A_358158_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/TeenSec.A!MTB"
        threat_id = "358158"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "TeenSec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "screensharetobrowser" ascii //weight: 1
        $x_1_2 = "appUsageHistoryFor" ascii //weight: 1
        $x_1_3 = "EmailAccountRemover" ascii //weight: 1
        $x_1_4 = "cp.secureteen.com/block/" ascii //weight: 1
        $x_1_5 = "ScreenMonitoringService" ascii //weight: 1
        $x_1_6 = "CallParrentActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

