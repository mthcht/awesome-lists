rule VirTool_Win32_Tater_B_2147794339_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Tater.B!MTB"
        threat_id = "2147794339"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Tater"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PrintSpoofer" ascii //weight: 1
        $x_1_2 = "SharpPotato" ascii //weight: 1
        $x_1_3 = "PotatoAPI" ascii //weight: 1
        $x_1_4 = "pipe\\spoolss" ascii //weight: 1
        $x_1_5 = "pipe\\srvsvc" ascii //weight: 1
        $x_1_6 = "EdpRpcRmsGetContainerIdentity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

