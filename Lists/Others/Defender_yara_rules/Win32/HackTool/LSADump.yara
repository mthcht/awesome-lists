rule HackTool_Win32_LSADump_2147796128_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/LSADump!dha"
        threat_id = "2147796128"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "LSADump"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\WINDOWS\\SYSTEM32\\lsasrv.DLL" wide //weight: 1
        $x_1_2 = "Get the SysKey to decrypt SAM entries (from registry or hives)" wide //weight: 1
        $x_2_3 = "ERROR kuhl_m_lsadump_sam ; CreateFile (SYSTEM hive) (0x%08x)" wide //weight: 2
        $x_2_4 = "LsaDump module" wide //weight: 2
        $x_1_5 = "LSA Key(s) : %u, default" wide //weight: 1
        $x_1_6 = "Ask LSA Server to retrieve SAM/AD entries (normal, patch on the fly or inject)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

