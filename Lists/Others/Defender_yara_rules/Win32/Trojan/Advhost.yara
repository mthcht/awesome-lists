rule Trojan_Win32_Advhost_A_2147597202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Advhost.A"
        threat_id = "2147597202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Advhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "78E1BDD1-9941-11cf-9756-00AA00C00908" wide //weight: 1
        $x_1_2 = "advertisementhost.com/ddd/index.php3?GETUPDATE=1" wide //weight: 1
        $x_1_3 = "Gwang.exe" wide //weight: 1
        $x_1_4 = "SOFTWARE\\System\\sysuid" wide //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_6 = "shell\\add\\command" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

