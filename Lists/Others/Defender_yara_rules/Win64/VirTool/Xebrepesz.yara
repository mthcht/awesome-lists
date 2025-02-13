rule VirTool_Win64_Xebrepesz_A_2147916124_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Xebrepesz.A!MTB"
        threat_id = "2147916124"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Xebrepesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".executeCommandAndHandleCD" ascii //weight: 1
        $x_1_2 = ".aesECBDncrypt" ascii //weight: 1
        $x_1_3 = ").Hostname" ascii //weight: 1
        $x_1_4 = ".injectTask" ascii //weight: 1
        $x_1_5 = {73 6f 63 6b 73 ?? 2e 48 61 6e 64 6c 65 43 6f 6e 6e 65 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_6 = ".TCPClient" ascii //weight: 1
        $x_1_7 = "RemoteAddr" ascii //weight: 1
        $x_1_8 = "maxPayloadSizeForWrite" ascii //weight: 1
        $x_1_9 = "SetSessionTicket" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

