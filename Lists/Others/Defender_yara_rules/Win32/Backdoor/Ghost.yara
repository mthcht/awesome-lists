rule Backdoor_Win32_Ghost_AA_2147826900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ghost.AA!MTB"
        threat_id = "2147826900"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ghost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Process32Next" ascii //weight: 1
        $x_1_2 = "Process32First" ascii //weight: 1
        $x_1_3 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_4 = "360tray" ascii //weight: 1
        $x_1_5 = "ESET" ascii //weight: 1
        $x_1_6 = "\\GHOSTBAK.exe" ascii //weight: 1
        $x_1_7 = "\\temp\\2011.exe" ascii //weight: 1
        $x_1_8 = "\\temp\\svchost.exe" ascii //weight: 1
        $x_1_9 = "3389.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

