rule Virus_Win32_Delf_F_2147594588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Delf.F"
        threat_id = "2147594588"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "File Folder" ascii //weight: 1
        $x_1_2 = "explorer" ascii //weight: 1
        $x_1_3 = "hh:nn" ascii //weight: 1
        $x_1_4 = "at %s cmd /c del \"%s\"" ascii //weight: 1
        $x_1_5 = "C:\\WINDOWS\\svchost.exe" ascii //weight: 1
        $x_1_6 = "C:\\WINDOWS\\svchost.dll" ascii //weight: 1
        $x_1_7 = "at %s %s firewall" ascii //weight: 1
        $x_1_8 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_9 = "FindNextFileA" ascii //weight: 1
        $x_1_10 = "FindFirstFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Delf_M_2147594653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Delf.M"
        threat_id = "2147594653"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "J@HIL" ascii //weight: 1
        $x_1_2 = "Norton Antivirus Server" ascii //weight: 1
        $x_1_3 = "HijackThis.exe" ascii //weight: 1
        $x_1_4 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 1
        $x_1_5 = "GameHouse.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

