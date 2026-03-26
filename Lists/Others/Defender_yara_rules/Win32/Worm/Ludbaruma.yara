rule Worm_Win32_Ludbaruma_AMTB_2147965638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ludbaruma!AMTB"
        threat_id = "2147965638"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ludbaruma"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Frmbabon" ascii //weight: 1
        $x_1_2 = "Shellexecute=Cewek_Imoet.exe" ascii //weight: 1
        $x_1_3 = "babon.SCR" ascii //weight: 1
        $x_1_4 = "\\All Users\\Start Menu\\Programs\\Startup\\Empty.pif" ascii //weight: 1
        $x_1_5 = "Mikocok Windoll" ascii //weight: 1
        $x_1_6 = "Beuh..pina musti nda ni lah. Hahaha..:)" ascii //weight: 1
        $x_1_7 = "It's free, u don't need to pay..:P" ascii //weight: 1
        $x_1_8 = "Notepad.exe C:\\wangsit.txt" ascii //weight: 1
        $n_100_9 = "Uninst.exe" ascii //weight: -100
        $n_100_10 = "Uninstaller.exe" ascii //weight: -100
        $n_100_11 = "Uninstal.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

