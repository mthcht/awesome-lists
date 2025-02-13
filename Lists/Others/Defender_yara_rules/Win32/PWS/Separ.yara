rule PWS_Win32_Separ_P_2147730433_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Separ.P"
        threat_id = "2147730433"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Separ"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%APPDATA%\\Local\\Adobe\\Pdf\\low\\" wide //weight: 1
        $x_1_2 = "adobe02.bat" ascii //weight: 1
        $x_1_3 = "adobel.vbs" ascii //weight: 1
        $x_1_4 = "adobepdf.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

