rule Virus_Win32_Ranlod_A_2147600141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Ranlod.gen!A"
        threat_id = "2147600141"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranlod"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "300"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SOFTWARE\\Mircosoft\\Windows\\CurrentVersion\\Run" ascii //weight: 100
        $x_100_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 100
        $x_100_3 = "You are infected with RP_Virus !" ascii //weight: 100
        $x_100_4 = "RP-Virus(New Random Payloder Virus)" ascii //weight: 100
        $x_20_5 = "\\rp.exe" ascii //weight: 20
        $x_20_6 = "RP_Virus" ascii //weight: 20
        $x_20_7 = ".pif" ascii //weight: 20
        $x_20_8 = ".scr" ascii //weight: 20
        $x_20_9 = "*.exe" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 5 of ($x_20_*))) or
            ((3 of ($x_100_*))) or
            (all of ($x*))
        )
}

