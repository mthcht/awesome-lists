rule Trojan_Win64_Zoader_ER_2147809570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zoader.ER!MTB"
        threat_id = "2147809570"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ".dll,DelNodeRunDLL32" ascii //weight: 3
        $x_3_2 = "SeShutdownPrivilege" ascii //weight: 3
        $x_3_3 = "CurrentVersion\\RunOnce" ascii //weight: 3
        $x_3_4 = "DoInfInstall" ascii //weight: 3
        $x_3_5 = "cmd /c" ascii //weight: 3
        $x_3_6 = "cd %APPDATA%" ascii //weight: 3
        $x_3_7 = "powershell Invoke-WebRequest " ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

