rule Worm_Win32_Dsiams_A_2147719070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dsiams.A!bit"
        threat_id = "2147719070"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dsiams"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 43 00 4f 00 50 00 59 00 20 00 28 00 20 00 40 00 57 00 4f 00 52 00 4b 00 49 00 4e 00 47 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-10] 2e 00 65 00 78 00 65 00 22 00 20 00 2c 00 20 00 40 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 43 00 4f 00 4d 00 4d 00 4f 00 4e 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 22 00 20 00 2c 00 20 00 39 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "RUNWAIT ( @COMSPEC & \" /c \" & \"rd %temp%\\ /s /q\" , \"\" , @SW_HIDE )" wide //weight: 1
        $x_1_4 = "FILESETATTRIB ( @APPDATACOMMONDIR & \"\\OSCHBR\\Autorun.inf\" , \"+SH\" )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

