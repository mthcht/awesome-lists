rule Trojan_Win32_BadIIS_EC_2147921626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadIIS.EC!MTB"
        threat_id = "2147921626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadIIS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HttpModRespDLLx64.pdb" ascii //weight: 1
        $x_1_2 = "HttpModDLL.dll" ascii //weight: 1
        $x_1_3 = "WinHttpCrackUrl" ascii //weight: 1
        $x_1_4 = "DebugBreak" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

