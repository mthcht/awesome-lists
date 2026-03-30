rule HackTool_Win32_WinActivator_2147787064_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/WinActivator!MTB"
        threat_id = "2147787064"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "WinActivator"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Delete Office reactivation task" wide //weight: 1
        $x_1_2 = "Use external KMS-Service" wide //weight: 1
        $x_1_3 = "SppExtComObj" wide //weight: 1
        $x_1_4 = "\\slmgr.vbs //NoLogo /ckms" wide //weight: 1
        $x_1_5 = "WNetAddConnection2A" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

