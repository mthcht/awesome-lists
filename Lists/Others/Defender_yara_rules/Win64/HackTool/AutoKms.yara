rule HackTool_Win64_AutoKms_DZ_2147923182_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/AutoKms.DZ!MTB"
        threat_id = "2147923182"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "AutoKms"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "kms.kmzs123.cn" ascii //weight: 2
        $x_2_2 = "Office 2016 PowerPointVL KMS Client" ascii //weight: 2
        $x_2_3 = "add \"HKCU\\Software\\Microsoft\\Office\\Common\\ClientTelemetry\" /v \"DisableTelemetry\" /t REG_DWORD /d 1 /f" ascii //weight: 2
        $x_1_4 = "//NoLogo /unpkey:" ascii //weight: 1
        $x_1_5 = "ACTIVATE" ascii //weight: 1
        $x_2_6 = "Office 2010 RTM Standard KMS Client" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

