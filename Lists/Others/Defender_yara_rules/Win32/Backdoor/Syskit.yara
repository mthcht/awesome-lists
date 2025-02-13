rule Backdoor_Win32_Syskit_A_2147742883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Syskit.A"
        threat_id = "2147742883"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Syskit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sc stop dllhost & timeout /t 10 & del C:\\Windows\\Temp\\BAK.exe" wide //weight: 2
        $x_2_2 = "powershell.exe" wide //weight: 2
        $x_2_3 = "kill_me" ascii //weight: 2
        $x_10_4 = "BAK.net4.dllhost.main\\BAK\\obj\\Release\\mscorsvw.pdb" ascii //weight: 10
        $x_10_5 = "C:\\Users\\sdfd\\Documents\\Visual Studio 2015\\Projects\\BAK.net4\\BAK\\obj\\Release\\BAK.pdb" ascii //weight: 10
        $x_10_6 = "C:\\Users\\sdfd\\Documents\\VisualStudio2015\\Projects\\BAK.net4\\BAK\\obj\\Release\\mscorsvw.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

