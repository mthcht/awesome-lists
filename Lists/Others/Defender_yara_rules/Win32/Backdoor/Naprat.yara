rule Backdoor_Win32_Naprat_AG_2147896091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Naprat.AG!MTB"
        threat_id = "2147896091"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Naprat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Login" wide //weight: 2
        $x_2_2 = "{Home}+{End}" wide //weight: 2
        $x_2_3 = "P.exe" wide //weight: 2
        $x_2_4 = "txtPassword" ascii //weight: 2
        $x_2_5 = "system32\\wmp.oca" ascii //weight: 2
        $x_2_6 = "YunIoQwJ" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

