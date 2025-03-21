rule Trojan_Win32_Xworm_A_2147895209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xworm.A!MTB"
        threat_id = "2147895209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$VB$Local_Port" ascii //weight: 1
        $x_1_2 = "$VB$Local_Host" ascii //weight: 1
        $x_1_3 = "get_Jpeg" ascii //weight: 1
        $x_1_4 = "get_ServicePack" ascii //weight: 1
        $x_1_5 = "Select * from AntivirusProduct" ascii //weight: 1
        $x_1_6 = "PCRestart" ascii //weight: 1
        $x_1_7 = "shutdown.exe /f /r /t 0" ascii //weight: 1
        $x_1_8 = "StopReport" ascii //weight: 1
        $x_1_9 = "StopDDos" ascii //weight: 1
        $x_1_10 = "sendPlugin" ascii //weight: 1
        $x_1_11 = "OfflineKeylogger Not EnabledOfflineKeylogger Not Enabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

