rule Trojan_Win32_StormServer_PC_2147949139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StormServer.PC!MTB"
        threat_id = "2147949139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StormServer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StormServer.dll" ascii //weight: 1
        $x_1_2 = "Welcome to use storm ddos" ascii //weight: 1
        $x_1_3 = "{%08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X}" ascii //weight: 1
        $x_1_4 = " /c  del " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

