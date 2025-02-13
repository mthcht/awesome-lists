rule Worm_Win32_Wofopey_A_2147638443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Wofopey.A"
        threat_id = "2147638443"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Wofopey"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DDXPPXCE" wide //weight: 1
        $x_1_2 = "DDXPPXFTPCE" wide //weight: 1
        $x_1_3 = "<///|WindowsSecurityAlertCE|1246351426614|\\>" wide //weight: 1
        $x_1_4 = "WinFireWalKillerl" ascii //weight: 1
        $x_1_5 = "VirusPPT-DDXPPX-FTP-CommandExecuter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

