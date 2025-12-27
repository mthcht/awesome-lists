rule Trojan_O97M_Madeba_NIT_2147955441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Madeba.NIT!MTB"
        threat_id = "2147955441"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Madeba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Magic number = 0x5A4D" ascii //weight: 2
        $x_2_2 = "WindowsPowerShell\\v1.0\\powershell.exe" ascii //weight: 2
        $x_1_3 = "CREATE_SUSPENDED" ascii //weight: 1
        $x_1_4 = "PAGE_EXECUTE_READWRITE" ascii //weight: 1
        $x_1_5 = "exec Bypass" ascii //weight: 1
        $x_1_6 = "RunPE(ByRef baImage()" ascii //weight: 1
        $x_1_7 = "://github.com/itm4n/VBA-RunPE" ascii //weight: 1
        $x_11_8 = "WriteProcessMemory(structProcessInformation.hProcess" ascii //weight: 11
        $x_11_9 = "ReadProcessMemory(structProcessInformation.hProcess" ascii //weight: 11
        $x_11_10 = "ResumeThread(structProcessInformation.hThread)" ascii //weight: 11
        $x_11_11 = "NtWriteVirtualMemory(structProcessInformation.hProcess" ascii //weight: 11
        $x_11_12 = "NtReadVirtualMemory(structProcessInformation.hProcess" ascii //weight: 11
        $x_11_13 = "NtResumeThread(structProcessInformation.hThread" ascii //weight: 11
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_11_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_11_*))) or
            (all of ($x*))
        )
}

