rule HackTool_Win32_StopDef_A_2147812078_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/StopDef.A"
        threat_id = "2147812078"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "StopDef"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StopDefender.pdb" ascii //weight: 1
        $x_1_2 = "TRUSTEDINSTALLER StopDefenderService() success" ascii //weight: 1
        $x_1_3 = "TRUSTEDINSTALLER ImpersonatedLoggedOnUser() success" ascii //weight: 1
        $x_1_4 = "Winlogon process not found" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

