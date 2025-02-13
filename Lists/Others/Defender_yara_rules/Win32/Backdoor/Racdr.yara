rule Backdoor_Win32_Racdr_A_2147678502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Racdr.A"
        threat_id = "2147678502"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Racdr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 78 69 61 6f 79 75 00}  //weight: 1, accuracy: High
        $x_1_2 = "WinRAR\\shell\\open\\command" ascii //weight: 1
        $x_1_3 = "\\Startup\\QQ" ascii //weight: 1
        $x_1_4 = "Sougou.exe" ascii //weight: 1
        $x_1_5 = "360tray.exe" ascii //weight: 1
        $x_1_6 = "/active:yes && net user guest ratpp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

