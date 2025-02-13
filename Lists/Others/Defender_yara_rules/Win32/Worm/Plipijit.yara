rule Worm_Win32_Plipijit_A_2147596440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Plipijit.A"
        threat_id = "2147596440"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Plipijit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableRegistryTools" wide //weight: 1
        $x_1_2 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\QQ" wide //weight: 1
        $x_1_3 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\loginaccount" wide //weight: 1
        $x_1_4 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\pjtWorm" wide //weight: 1
        $x_1_5 = "c:\\windows\\system32\\drivers\\etc\\hosts" wide //weight: 1
        $x_1_6 = "shell\\open\\Command=NTDETECT.exe" wide //weight: 1
        $x_1_7 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_8 = "C:\\program files\\itemlog\\" wide //weight: 1
        $x_1_9 = ":\\autorun.inf" wide //weight: 1
        $x_1_10 = "www.876992.cn www.google.com" wide //weight: 1
        $x_1_11 = "c:\\QQLogin.exe" wide //weight: 1
        $x_1_12 = "[AutoRun]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

