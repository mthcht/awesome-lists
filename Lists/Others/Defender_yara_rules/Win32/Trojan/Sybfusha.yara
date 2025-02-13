rule Trojan_Win32_Sybfusha_A_2147706780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sybfusha.A"
        threat_id = "2147706780"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sybfusha"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "\\sysfucker\\Project" wide //weight: 4
        $x_1_2 = "start c:\\windows\\notfall.bat" wide //weight: 1
        $x_1_3 = "shutdown -s -t 10 -f" wide //weight: 1
        $x_1_4 = "cmd /c erase /f %HOMEDRIVE%\\boot.ini" wide //weight: 1
        $x_1_5 = "cmd /c assoc .exe=WinRAR" wide //weight: 1
        $x_1_6 = "net user Administrator /active:no" wide //weight: 1
        $x_1_7 = "/c del /q %windir%\\repair\\*.*" wide //weight: 1
        $x_1_8 = "cmd /c tskill /f icq" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

