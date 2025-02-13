rule Backdoor_MSIL_Orcusrot_A_2147709931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Orcusrot.A"
        threat_id = "2147709931"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Orcusrot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DDoSCommunication" ascii //weight: 1
        $x_1_2 = "HttpFlood" ascii //weight: 1
        $x_1_3 = "IcmpFlood" ascii //weight: 1
        $x_1_4 = "SynFlood" ascii //weight: 1
        $x_1_5 = "UdpFlood" ascii //weight: 1
        $x_1_6 = "ResponseAttackOpen" ascii //weight: 1
        $x_1_7 = "SubmitKeylogs" ascii //weight: 1
        $x_1_8 = "GetKeyLog" ascii //weight: 1
        $x_1_9 = "GetPassword" ascii //weight: 1
        $x_1_10 = "RecoveredCookie" ascii //weight: 1
        $x_1_11 = "RecoveredPassword" ascii //weight: 1
        $x_1_12 = "UpdateFromUrl" ascii //weight: 1
        $x_1_13 = "GetWebcam" ascii //weight: 1
        $x_1_14 = "ReverseProxy" ascii //weight: 1
        $x_1_15 = "RemoteDesktopCommunication" ascii //weight: 1
        $x_1_16 = "StartMassDownload" ascii //weight: 1
        $x_1_17 = "DownloadAndOpenFile" ascii //weight: 1
        $x_1_18 = "DisableMonitor" ascii //weight: 1
        $x_1_19 = "DisableTaskmanager" ascii //weight: 1
        $x_1_20 = "DisableUserInput" ascii //weight: 1
        $x_1_21 = "HangSystem" ascii //weight: 1
        $x_1_22 = "HideTaskbar" ascii //weight: 1
        $x_1_23 = "HiddenStart" ascii //weight: 1
        $x_1_24 = "AntiDebugger" ascii //weight: 1
        $x_1_25 = "AntiTcpAnalyzer" ascii //weight: 1
        $x_1_26 = "ProtectFromVMs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (20 of ($x*))
}

