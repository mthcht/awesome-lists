rule Virus_Win32_Ridnu_A_2147610242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Ridnu.gen!A"
        threat_id = "2147610242"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Ridnu"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mr_CoolFace.scr" ascii //weight: 1
        $x_1_2 = ".pif .bat .com .scr .exe" ascii //weight: 1
        $x_1_3 = {8a 10 8a ca 3a 16 75 1c 3a cb 74 14 8a 50 01 8a ca 3a 56 01 75 0e 83 c0 02 83 c6 02 3a cb 75 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Ridnu_C_2147619435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Ridnu.C"
        threat_id = "2147619435"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Ridnu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\*.exe" ascii //weight: 10
        $x_10_2 = "DEULLEDO-X.SCR" ascii //weight: 10
        $x_10_3 = ":\\autorun.inf" ascii //weight: 10
        $x_10_4 = "\\system32\\logonui.scr" ascii //weight: 10
        $x_10_5 = "\\program files\\winamp\\winamp" ascii //weight: 10
        $x_1_6 = "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WorkgroupCrawler\\Shares" ascii //weight: 1
        $x_1_8 = "DisableTaskMgr" ascii //weight: 1
        $x_1_9 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

