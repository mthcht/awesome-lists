rule Trojan_Win32_AutoitMalex_RA_2147843241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitMalex.RA!MTB"
        threat_id = "2147843241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitMalex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$MUTEX = \"win.com.exe\"" ascii //weight: 1
        $x_1_2 = "FILECOPY ( @SCRIPTFULLPATH , @SYSTEMDIR & \"\\image.jpg.exe\" )" ascii //weight: 1
        $x_1_3 = "FILECOPY ( @SCRIPTFULLPATH , @SYSTEMDIR & \"\\record of the world.exe\" )" ascii //weight: 1
        $x_1_4 = "FILECOPY ( @SCRIPTFULLPATH , @SYSTEMDIR & \"\\windows2000.exe\" )" ascii //weight: 1
        $x_1_5 = "FILECOPY ( @SCRIPTFULLPATH , @STARTUPDIR & \"\\Livre.pl.exe\" )" ascii //weight: 1
        $x_1_6 = "REGDELETE ( \"HKLM\" )" ascii //weight: 1
        $x_1_7 = "REGDELETE ( \"HKU\" )" ascii //weight: 1
        $x_1_8 = "REGDELETE ( \"HKCR\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

