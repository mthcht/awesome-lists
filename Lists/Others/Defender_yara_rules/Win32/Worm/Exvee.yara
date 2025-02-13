rule Worm_Win32_Exvee_A_2147581996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Exvee.A"
        threat_id = "2147581996"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Exvee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Explorer\\IEXPLORE.EXE" ascii //weight: 1
        $x_2_2 = "\\drivers\\etc\\hosts" ascii //weight: 2
        $x_2_3 = "css.css" ascii //weight: 2
        $x_1_4 = "\\config.ini" ascii //weight: 1
        $x_1_5 = "\\tempIcon.exe" ascii //weight: 1
        $x_2_6 = "[autorun]@#Open=tool.exe@#Shellexecute=tool.exe@#Shell" ascii //weight: 2
        $x_1_7 = ":\\autorun.inf" ascii //weight: 1
        $x_2_8 = "<script language=\"javascript\" src=\"http://%" ascii //weight: 2
        $x_1_9 = ".HTML" ascii //weight: 1
        $x_1_10 = ".ASPX" ascii //weight: 1
        $x_1_11 = "System Boot Check" ascii //weight: 1
        $x_2_12 = "Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_2_13 = "CreateRemoteThread" ascii //weight: 2
        $x_2_14 = "WriteProcessMemory" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((7 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

