rule Backdoor_Win32_Amerced_A_2147609128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Amerced.A"
        threat_id = "2147609128"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Amerced"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(Right Arrow)" wide //weight: 1
        $x_1_2 = "(Backspace)" wide //weight: 1
        $x_1_3 = "pwdchanged" wide //weight: 1
        $x_1_4 = "erroldpwd" wide //weight: 1
        $x_1_5 = "Windows Millennium" wide //weight: 1
        $x_1_6 = "High Color (" wide //weight: 1
        $x_1_7 = "Shell_TrayWnd" wide //weight: 1
        $x_1_8 = "id=\"atom(wizardroot)\">" wide //weight: 1
        $x_1_9 = "snifret" wide //weight: 1
        $x_1_10 = "systemdrive" wide //weight: 1
        $x_1_11 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_12 = "Daemon.VolumeControl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

