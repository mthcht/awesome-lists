rule Trojan_Win32_Niktol_RPY_2147893064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Niktol.RPY!MTB"
        threat_id = "2147893064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Niktol"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "set hid_exec" ascii //weight: 1
        $x_1_2 = "%hid_executable%" ascii //weight: 1
        $x_1_3 = "del /q /f %hid_executable% >nul 2>&1" ascii //weight: 1
        $x_1_4 = "if exist \"%tmp%\\zzz\" (set check=executed) else (set check=not_executed)" ascii //weight: 1
        $x_1_5 = "HideExtractAnimation=1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

