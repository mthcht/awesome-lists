rule SupportScam_Win32_Bludit_A_2147724206_0
{
    meta:
        author = "defender2yara"
        detection_name = "SupportScam:Win32/Bludit.A"
        threat_id = "2147724206"
        type = "SupportScam"
        platform = "Win32: Windows 32-bit platform"
        family = "Bludit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GUICTRLCREATELABEL ( \"A problem has been detected and Windows" wide //weight: 1
        $x_1_2 = "RUN ( \"taskmgr.exe\" , \"\" , @SW_DISABLE )" wide //weight: 1
        $x_1_3 = "HOTKEYSET ( \"+!c\" , \"ExitBlueScr\" )" wide //weight: 1
        $x_1_4 = "( @SCRIPTFULLPATH , @STARTUPDIR & \"\\svchost.lnk\" )" wide //weight: 1
        $x_1_5 = "& \"*** STOP: 0x000000" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

