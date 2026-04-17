rule HackTool_Win64_RedSun_DA_2147967217_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/RedSun.DA!MTB"
        threat_id = "2147967217"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "RedSun"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\??\\pipe\\REDSUN" ascii //weight: 1
        $x_1_2 = "HarddiskVolumeShadowCopy" ascii //weight: 1
        $x_1_3 = "%TEMP%\\RS-" ascii //weight: 1
        $x_1_4 = "\\??\\C:\\Windows\\System32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

