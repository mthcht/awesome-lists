rule Trojan_Win32_Autoitinjector_S_2147767843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autoitinjector.S!ibt"
        threat_id = "2147767843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoitinjector"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "57"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Windows\\System32\\wbem\\wmic.exe product where name=\"\"Microsoft Security Client\"\" call uninstall /nointeractive" wide //weight: 1
        $x_1_2 = "IF PROCESSEXISTS ( \"msseces.exe\" ) THEN" wide //weight: 1
        $x_1_3 = "IF FILEEXISTS ( @DESKTOPDIR & \"\\secret.txt\" ) THEN" wide //weight: 1
        $x_1_4 = "IF PROCESSEXISTS ( \"joeboxcontrol.exe\" ) OR PROCESSEXISTS ( \"joeboxserver.exe\" ) THEN" wide //weight: 1
        $x_10_5 = "FILEINSTALL ( \"C:\\Users\\Admin\\Desktop\\HACK21\\Cheat\\Cheat.exe\" , \"C:\\programdata\\install\\cheat.exe" wide //weight: 10
        $x_10_6 = "FILEINSTALL ( \"D:\\NewERA_2\\ETERNAL_MINER\\ex20mac\\taskhost.exe\" , \"C:\\ProgramData\\RealtekHD\\taskhost.exe" wide //weight: 10
        $x_20_7 = "RUN ( @COMSPEC & \" /c \" & \"netsh advfirewall firewall add rule name=" wide //weight: 20
        $x_20_8 = "RUN ( @COMSPEC & \" /c \" & \"icacls C:\\AdwCleaner /deny %username%:(OI)(CI)(F)\" , \"\" , @SW_HIDE" wide //weight: 20
        $x_20_9 = "RUN ( @COMSPEC & \" /c icacls \"\"C:\\Program Files\\AVAST Software\"\" /deny %username%:(OI)(CI)(F)\" , \"\" , @SW_HIDE )" wide //weight: 20
        $x_20_10 = "RUN ( @COMSPEC & \" /c icacls \"\"C:\\Program Files (x86)\\AVAST Software\"\" /deny %username%:(OI)(CI)(F)\" , \"\" , @SW_HIDE )" wide //weight: 20
        $x_20_11 = "RUN ( @COMSPEC & \" /c icacls \"\"C:\\Program Files (x86)\\AVG\"\" /deny %username%:(OI)(CI)(F)\" , \"\" , @SW_HIDE )" wide //weight: 20
        $x_20_12 = "RUN ( @COMSPEC & \" /c icacls \"\"C:\\ProgramData\\ESET\"\" /deny %username%:(OI)(CI)(F)\" , \"\" , @SW_HIDE )" wide //weight: 20
        $x_5_13 = "$HCONN , $FTP_XMRIGCPU64 , \"C:\\Programdata\\Install\" & \"\" & $FTP_XMRIGCPU64 )" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_20_*) and 2 of ($x_10_*))) or
            ((3 of ($x_20_*))) or
            (all of ($x*))
        )
}

