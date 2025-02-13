rule Trojan_MSIL_MassKeyLogger_MK_2147772760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassKeyLogger.MK!MTB"
        threat_id = "2147772760"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MassLogger" ascii //weight: 1
        $x_1_2 = "loggerData" ascii //weight: 1
        $x_1_3 = "_hookID" ascii //weight: 1
        $x_1_4 = "SetWindowsHookEx" ascii //weight: 1
        $x_1_5 = "CallNextHookEx" ascii //weight: 1
        $x_1_6 = "System.Net.Mail" ascii //weight: 1
        $x_1_7 = "NetworkCredential" ascii //weight: 1
        $x_1_8 = "EnableAntiSandboxie" ascii //weight: 1
        $x_1_9 = "EnableWDExclusion" ascii //weight: 1
        $x_1_10 = "EnableKeylogger" ascii //weight: 1
        $x_1_11 = {4d 61 73 73 4c 6f 67 67 65 72 [0-20] 72 65 73 6f 75 72 63 65 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

