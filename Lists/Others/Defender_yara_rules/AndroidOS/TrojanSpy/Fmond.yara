rule TrojanSpy_AndroidOS_Fmond_A_2147805863_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fmond.A!MTB"
        threat_id = "2147805863"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fmond"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RemoteCameraActivity" ascii //weight: 1
        $x_1_2 = "isSpyEnabled" ascii //weight: 1
        $x_1_3 = "enableSpyCallOrInterceptCall" ascii //weight: 1
        $x_1_4 = "Lcom/vvt/callmanager/ref/command/RemoteAddMonitor" ascii //weight: 1
        $x_1_5 = "CallLogCapture" ascii //weight: 1
        $x_1_6 = "ChromeCapture" ascii //weight: 1
        $x_1_7 = "GmailCapture" ascii //weight: 1
        $x_1_8 = "RemoteAddSmsIntercept" ascii //weight: 1
        $x_1_9 = "/callmon.zip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

