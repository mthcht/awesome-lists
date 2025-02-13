rule Virus_Win32_Autorun_B_2147597961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Autorun.B"
        threat_id = "2147597961"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bclogsvr.ini" ascii //weight: 1
        $x_1_2 = "Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_3 = "Windows\\CurrentVersion\\policies\\Explorer\\Run" ascii //weight: 1
        $x_1_4 = "flash.bpa.nu" ascii //weight: 1
        $x_1_5 = "svchost.exe" ascii //weight: 1
        $x_1_6 = "http://%s:%d/index.cgi" ascii //weight: 1
        $x_1_7 = "Generic Host Process for Win32 Services" wide //weight: 1
        $x_1_8 = "GetLogicalDriveStringsA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Autorun_2147598019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Autorun"
        threat_id = "2147598019"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "ping 127.1 -n 5 >nul 2>nul >1.bat&echo del" wide //weight: 4
        $x_4_2 = "exe >>1.bat&echo del 1.bat >>1.bat&1.bat" wide //weight: 4
        $x_4_3 = "exe /c net stop KPfwSvc" wide //weight: 4
        $x_4_4 = "exe /c del %SystemRoot%\\system" wide //weight: 4
        $x_4_5 = "cmd.exe /c net stop McShield" wide //weight: 4
        $x_2_6 = "stop \"Norton AntiVirus Server\"" wide //weight: 2
        $x_1_7 = "/f1.jpg" wide //weight: 1
        $x_1_8 = "/gx.jpg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Autorun_OE_2147602084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Autorun.OE"
        threat_id = "2147602084"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 85 f4 fe ff ff 68 38 16 40 00 50 ff d6 59 c7 45 fc 01 00 00 00 85 c0 59 74 03 89 5d fc 8d 85 d0 fe ff ff 50 57 e8 49 12 00 00 85 c0 75 bd 39 5d fc 75 44 53 be 18 16 40 00 53 56 68 f0 15 40 00 53 e8 57 12 00 00 53 53 53 56 8b 35 80 13 40 00 68 e8 15 40 00 53 ff d6 53 bf c8 15 40 00 53 57 68 a0 15 40 00 53 e8 32 12 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

