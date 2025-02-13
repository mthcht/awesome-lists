rule Backdoor_MacOS_orat_C_2147850675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/orat.C!MTB"
        threat_id = "2147850675"
        type = "Backdoor"
        platform = "MacOS: "
        family = "orat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "orat_protocol/DialTCP" ascii //weight: 1
        $x_1_2 = "orat_protocol/DialSTCP" ascii //weight: 1
        $x_1_3 = "orat_protocol/DialSUDP" ascii //weight: 1
        $x_1_4 = "orat/cmd/agent/app.(*App).DownloadFile" ascii //weight: 1
        $x_1_5 = "orat/cmd/agent/app.(*App).KillSelf" ascii //weight: 1
        $x_1_6 = "orat/cmd/agent/app.(*App).NewNetConn" ascii //weight: 1
        $x_1_7 = "orat/cmd/agent/app.(*App).NewProxyConn" ascii //weight: 1
        $x_1_8 = "orat/cmd/agent/app.(*App).NewShellConn" ascii //weight: 1
        $x_1_9 = "orat/cmd/agent/app.(*App).PortScan" ascii //weight: 1
        $x_1_10 = "orat/cmd/agent/app.(*App).registerRouters" ascii //weight: 1
        $x_1_11 = "orat/cmd/agent/app.(*App).Screenshot" ascii //weight: 1
        $x_1_12 = "orat/cmd/agent/app.(*App).UploadFile" ascii //weight: 1
        $x_1_13 = "orat/utils" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

