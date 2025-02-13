rule Trojan_Win32_Wimepud_A_2147707552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wimepud.A"
        threat_id = "2147707552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wimepud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RUN ( FILEGETSHORTNAME ( @TEMPDIR & \"\\lsass.exe\" ) & \" /Autoit3ExecuteScript" wide //weight: 1
        $x_1_2 = "FILECOPY ( @SCRIPTFULLPATH , @APPDATADIR & \"\\lsass.exe\" )" wide //weight: 1
        $x_1_3 = "BINARYTOSTRING ( INETREAD ( \"http://api.hostip.info/country.php\" ) )" wide //weight: 1
        $x_1_4 = "= @TEMPDIR & \"\\kill.tmp\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wimepud_B_2147707555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wimepud.B"
        threat_id = "2147707555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wimepud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RUN ( @APPDATADIR & \"\\lssass.exe\" )" wide //weight: 1
        $x_1_2 = "RUN ( @TEMPDIR & \"\\scratch.bat\" , @TEMPDIR , @SW_HIDE )" wide //weight: 1
        $x_1_3 = "\\Run\" , \"Microsoft\" , \"REG_SZ\" , @APPDATADIR & \"\\" wide //weight: 1
        $x_1_4 = "INETGET ( \"http://www.whatismyip.com/?rnd1=\" & RANDOM ( 1 , 65536 )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

