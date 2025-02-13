rule VirTool_Win32_AutInject_CA_2147706342_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.CA"
        threat_id = "2147706342"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$TROJANPATH = @TEMPDIR & \"\\\" & \"" wide //weight: 1
        $x_1_2 = "$TROJANKEY = \"" wide //weight: 1
        $x_1_3 = "$FULSCPT = FILEOPEN ( $TROJANPATH , 0 )" wide //weight: 1
        $x_1_4 = "$S_ENCRYPTPASSWORD = \"ioiooiioio\"" wide //weight: 1
        $x_1_5 = "$OPCODE = \"0x89C04150535657524889CE4889D7FCB2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_AutInject_CB_2147706367_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.CB"
        threat_id = "2147706367"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEGETSHORTNAME ( @TEMPDIR & \"\\\" & RANDOM ( 4 , 9 , 1 ) & $EXTENT )" wide //weight: 1
        $x_1_2 = "[ 2 ] , 8888 ) )" wide //weight: 1
        $x_1_3 = "( \"0x5C4D6963726F736F66742E4E45545C4672616D65776F726B5C" wide //weight: 1
        $x_1_4 = "( \"0x5368656C6C457865637574652846696C6547657453686F72744E616D6528246163636363636329" wide //weight: 1
        $x_1_5 = "$PEPEDAL = \"gebek" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_AutInject_CC_2147706389_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.CC"
        threat_id = "2147706389"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 00 4c 00 45 00 45 00 50 00 20 00 28 00 20 00 31 00 ?? ?? 30 00 30 00 30 00 20 00 29 00 [0-4] 20 00 4c 00 4f 00 43 00 41 00 4c 00 20 00 24 00}  //weight: 1, accuracy: Low
        $x_1_2 = " = \"0x4D5A50000200000004000F00FFFF0000B80000000000000040001A0000000" wide //weight: 1
        $x_1_3 = " = \"0x4D5A90000300000004000000FFFF0000B8000000000000004000000000000" wide //weight: 1
        $x_1_4 = " & CHR ( ASC ( STRINGMID ( $" wide //weight: 1
        $x_1_5 = {20 00 2c 00 20 00 40 00 53 00 43 00 52 00 49 00 50 00 54 00 46 00 55 00 4c 00 4c 00 50 00 41 00 54 00 48 00 20 00 29 00 0d 00 0a 00 20 00 46 00 55 00 4e 00 43 00 20 00}  //weight: 1, accuracy: High
        $x_1_6 = {20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 2d 00 20 00 [0-4] 20 00 29 00 [0-4] 20 00 4e 00 45 00 58 00 54 00 [0-4] 20 00 52 00 45 00 54 00 55 00 52 00 4e 00 20 00 24 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule VirTool_Win32_AutInject_CD_2147706390_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.CD"
        threat_id = "2147706390"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"netsh\" , \"firewall add allowedprogram \" & CHRW ( 34 ) & @AUTOITEXE" wide //weight: 1
        $x_1_2 = "( \"MutexLolByteLSX\" )" wide //weight: 1
        $x_1_3 = "@TEMPDIR & \"\\scratch.bat\"" wide //weight: 1
        $x_1_4 = "RUNPE ( $INJECTION ," wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_AutInject_CD_2147706390_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.CD"
        threat_id = "2147706390"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"&cn=\" & @COMPUTERNAME & \"&un=\" & @USERNAME" wide //weight: 1
        $x_1_2 = "( \"0x5C\" ) ) & RANDOM ( 45 , 60 , 1 ) & RANDOM ( 45 , 60 , 1 ) &" wide //weight: 1
        $x_1_3 = "\\Explorer\\Shell Folders\" , \"Local AppData\" )" wide //weight: 1
        $x_1_4 = "( \"0x6578652E7265746972776C71735C\" ) )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_AutInject_CF_2147707228_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.CF"
        threat_id = "2147707228"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= DLLCALL ( \"Kernel32\" , \"ptr\" , \"GetModuleFileNameA\" , \"ptr\" , $" wide //weight: 1
        $x_1_2 = "ISEhTk9UIFJFTE9DQVRBQkxFIE1PRFVMRS4gSSBXSUxMIFRSWSBCVVQgVEhJUyBNQVkgTk9UIFdPUkshISF=" wide //weight: 1
        $x_1_3 = "ZHdvcmQgVmlydHVhbEFkZHJlc3M7IGR3b3JkIFNpemW=" wide //weight: 1
        $x_1_4 = "U2l6ZU9mSGVhZGVycw==" wide //weight: 1
        $x_1_5 = "ZHdvcmQgQ29udGV4dEZsYWdzOw==" wide //weight: 1
        $x_1_6 = "Q2FsbFdpbmRvd1Byb2M=" wide //weight: 1
        $x_1_7 = "V3JpdGVQcm9jZXNzTWVtb3J5" wide //weight: 1
        $x_1_8 = "VmlydHVhbEFsbG9jRXg=" wide //weight: 1
        $x_1_9 = "SXNXb3c2NFByb2Nlc3M=" wide //weight: 1
        $x_1_10 = "TnRVbm1hcFZpZXdPZlNlY3Rpb24=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_AutInject_CG_2147707519_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.CG"
        threat_id = "2147707519"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= CHR ( 48 ) & CHR ( 120 ) & CHR ( 67 ) & CHR ( 56 ) & CHR ( 49 ) & CHR ( 48 ) & CHR ( 48 ) & CHR ( 49 )" wide //weight: 1
        $x_1_2 = {52 00 45 00 47 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 22 00 48 00 4b 00 22 00 20 00 26 00 20 00 24 00 [0-32] 20 00 26 00 20 00 22 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 22 00 20 00 26 00 20 00 24 00 [0-32] 20 00 26 00 20 00 22 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 22 00 20 00 26 00 20 00 24 00 [0-32] 20 00 26 00 20 00 22 00 5c 00 52 00 75 00 6e 00 22 00 20 00 2c 00 20 00 40 00 53 00 43 00 52 00 49 00 50 00 54 00 4e 00 41 00 4d 00 45 00 20 00 2c 00 20 00 22 00 52 00 45 00 47 00 5f 00 53 00 5a 00 22 00 20 00 2c 00 20 00 40 00 53 00 43 00 52 00 49 00 50 00 54 00 46 00 55 00 4c 00 4c 00 50 00 41 00 54 00 48 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_3 = "FILEINSTALL ( \"td132ccwa2.gec\" , @TEMPDIR & \"\\td132ccwa2.gec\" , 1 )" wide //weight: 1
        $x_1_4 = "FILEOPEN ( @TEMPDIR & \"\\td132ccwa2.gec\" , 16 )" wide //weight: 1
        $x_1_5 = {28 00 20 00 31 00 31 00 34 00 20 00 29 00 20 00 26 00 20 00 [0-32] 20 00 28 00 20 00 31 00 31 00 34 00 20 00 29 00 20 00 26 00 20 00 [0-32] 20 00 28 00 20 00 31 00 30 00 31 00 20 00 29 00 20 00 26 00 20 00 24 00 [0-32] 20 00 26 00 20 00 [0-32] 20 00 28 00 20 00 39 00 32 00 20 00 29 00 20 00 26 00 20 00 [0-32] 20 00 28 00 20 00 38 00 32 00 20 00 29 00 20 00 26 00 20 00 [0-32] 20 00 28 00 20 00 31 00 31 00 37 00 20 00 29 00 20 00 26 00 20 00 [0-32] 20 00 28 00 20 00 31 00 31 00 30 00 20 00 29 00 20 00 2c 00 20 00 40 00 53 00 43 00 52 00 49 00 50 00 54 00 4e 00 41 00 4d 00 45 00 20 00 2c 00}  //weight: 1, accuracy: Low
        $x_1_6 = ", @SYSTEMDIR & \"\\WerFault.exe\" )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_AutInject_CG_2147707519_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.CG"
        threat_id = "2147707519"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"filewrite(FileOpen(@TempDir & \"\"\\lol.bin\"\",18), \"\"0x\"\" & $" wide //weight: 1
        $x_1_2 = ")ShellExecute( @ScriptFullPath,  \"\"/AutoIt3ExecuteScript \"\" & @TempDir & \"\"\\lol.bin\"\", @ScriptDir" wide //weight: 1
        $x_1_3 = "SHELLEXECUTE ( @SCRIPTFULLPATH , \"/AutoI\" & \"t3ExecuteScript \" & @TEMPDIR & \"\\lol\" & \".bi\" & \"n\" , @SCRIPTDIR )" wide //weight: 1
        $x_1_4 = "FILEWRITE ( FILEOPEN ( @TEMPDIR & \"\\lol\" & \".bi\" & \"n\" , 18 ) , $SUPERALL )" wide //weight: 1
        $x_1_5 = "SHELLEXECUTE ( @SCRIPTFULLPATH , \"/AutoI\" & \"t3ExecuteScript \" & @TEMPDIR & $XXXX , @SCRIPTDIR )" wide //weight: 1
        $x_1_6 = "FILEWRITE ( FILEOPEN ( @TEMPDIR & $XXXX , 18 ) , $SUPERALL )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_AutInject_CH_2147707784_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.CH"
        threat_id = "2147707784"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEDELETE ( @APPDATACOMMONDIR & \"\\\" &" wide //weight: 1
        $x_1_2 = ".folder\" , @SCRIPTDIR )" wide //weight: 1
        $x_1_3 = ".path\" , @SCRIPTFULLPATH )" wide //weight: 1
        $x_1_4 = ".exe\" , @APPDATACOMMONDIR &" wide //weight: 1
        $x_1_5 = ".au3\" , @APPDATACOMMONDIR &" wide //weight: 1
        $x_1_6 = "SHELLEXECUTE ( @APPDATACOMMONDIR &" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_AutInject_CI_2147708153_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.CI"
        threat_id = "2147708153"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RUN ( @APPDATACOMMONDIR & " wide //weight: 1
        $x_1_2 = "& CHR ( 46 ) & CHR ( 97 ) & CHR ( 117 ) & CHR ( 51 )" wide //weight: 1
        $x_1_3 = "& CHR ( 46 ) & CHR ( 101 ) & CHR ( 120 ) & CHR ( 101 )" wide //weight: 1
        $x_1_4 = "FILEWRITE ( @APPDATACOMMONDIR &" wide //weight: 1
        $x_1_5 = "& CHR ( 46 ) & \"path\" , @SCRIPTFULLPATH )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_AutInject_CJ_2147708504_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.CJ"
        threat_id = "2147708504"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "goto start\" & @CRLF & \"del" wide //weight: 1
        $x_1_2 = "[ 1 ] & \" -aoa \" & \" -p\" &" wide //weight: 1
        $x_1_3 = "] = \"0x" wide //weight: 1
        $x_1_4 = "] = \" *.swf" wide //weight: 1
        $x_1_5 = "( 0 , 2 , RANDOM ( 5 , 10 ) ) , 1 )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_AutInject_CJ_2147708504_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.CJ"
        threat_id = "2147708504"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"\\Microsoft.NET\\Framework\\v2.0.50727\\RegSvcs.exe\"" wide //weight: 1
        $x_1_2 = "= \"painwithoutlove\"" wide //weight: 1
        $x_1_3 = "RETURN EXECUTE ( BINTRANSLAT ( $NOTSEXY & $SEXY ) )" wide //weight: 1
        $x_2_4 = "= \"0x446C6C43616C6C28227573657233322E646C6C222C\"" wide //weight: 2
        $x_2_5 = "= \"2022696E74222C202243616C6C57696E646F7750726F6357222C2022707472222C20446C6C53747\"" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_AutInject_CJ_2147708504_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.CJ"
        threat_id = "2147708504"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"/\" & \"A\" & \"utoI\" & \"t3\" & \"E\" & \"x\" & \"ec\" & \"u\" & \"teSc\" & \"ript \" & @TEMPDIR & \"\\\" & \"l\" & \"ol\" & \".\" & \"bi\" & \"n\"" wide //weight: 1
        $x_1_2 = "$SUPERALL = \"0x\" & $ALLDATA1" wide //weight: 1
        $x_1_3 = "FILEWRITE ( FILEOPEN ( @TEMPDIR & \"\\lol\" & \".bi\" & \"n\" , 18 ) , $SUPERALL )" wide //weight: 1
        $x_1_4 = "FILEWRITE ( FILEOPEN ( $DETEMP & \"\\lol\" & \".bi\" & \"n\" , 18 ) , $SUPERALL )" wide //weight: 1
        $x_1_5 = "= \"/AutoIt3ExecuteScript \" & $DETEMP & \"\\lol.bin\"" wide //weight: 1
        $x_1_6 = "EXECUTE ( \"filewrite(FileOpen($detemp & \"\"\\lol\"\" & \"\".bi\"\" & \"\"n\"\",18), $SuperAll)\" )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_AutInject_CK_2147709025_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.CK"
        threat_id = "2147709025"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[ 0 ] = \"A407B24B41A4AEA6C7DE8D84838569E8\"" wide //weight: 1
        $x_1_2 = {3d 00 20 00 40 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 22 00 [0-80] 20 00 3d 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 40 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 44 00 49 00 52 00 20 00 2c 00 20 00 31 00 20 00 2c 00 20 00 32 00 20 00 29 00 20 00 26 00 20 00 22 00 5c 00 22 00}  //weight: 1, accuracy: Low
        $x_1_3 = ", \":start\" & @CRLF & \"del \"\"\" & @AUTOITEXE & \"\"\"\" & @CRLF & \"IF EXIST \"\"\" & @AUTOITEXE & \"\"\" goto start\"" wide //weight: 1
        $x_1_4 = {53 00 4c 00 45 00 45 00 50 00 20 00 28 00 20 00 32 00 30 00 30 00 30 00 30 00 20 00 29 00 [0-8] 57 00 48 00 49 00 4c 00 45 00 20 00 46 00 49 00 4c 00 45 00 45 00 58 00 49 00 53 00 54 00 53 00 20 00 28 00 20 00 24 00 [0-80] 20 00 5b 00 20 00 30 00 20 00 5d 00 20 00 29 00 [0-8] 46 00 49 00 4c 00 45 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 28 00 20 00 24 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_AutInject_CL_2147709028_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.CL"
        threat_id = "2147709028"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "( \"exe.iupva\" ) ) THEN" wide //weight: 1
        $x_1_2 = "( \"exe.tnegabd\" ) ) THEN" wide //weight: 1
        $x_1_3 = "( \"exe\" ) & \" \"\"\" & @APPDATADIR &" wide //weight: 1
        $x_1_4 = "( \"3ua\" ) &" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_AutInject_CN_2147720814_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.CN!bit"
        threat_id = "2147720814"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "$SVALUENAME = \"DisableTaskMg" wide //weight: 1
        $x_1_3 = "Select * from AntiVirusProduct" wide //weight: 1
        $x_1_4 = "hostname|encryptedPassword|encryptedUsername" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_AutInject_CO_2147724764_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.CO!bit"
        threat_id = "2147724764"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pjoaxovpkm" wide //weight: 1
        $x_1_2 = "texdekoxbpxcg" wide //weight: 1
        $x_1_3 = "$J30OAV = EXECUTE" wide //weight: 1
        $x_1_4 = "@APPDATADIR & WFBDFEONVMJ" wide //weight: 1
        $x_1_5 = "@TEMPDIR & WFBDFEONVMJ" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_AutInject_CX_2147734558_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.CX!bit"
        threat_id = "2147734558"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "648B35300000008B760C8B760C8B0C8B760C8B" wide //weight: 1
        $x_1_2 = "8B473C8B44387803C78B5020" wide //weight: 1
        $x_1_3 = "C78570FFFFFF99B04806" wide //weight: 1
        $x_1_4 = "c78558ffffff793a3c07" wide //weight: 1
        $x_1_5 = "c7855cffffff794a8a0b" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_AutInject_CY_2147734580_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.CY!bit"
        threat_id = "2147734580"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {36 00 e7 00 34 00 38 00 42 00 e7 00 33 00 e7 00 35 00 e7 00 33 00 30 00 30 00 30 00 30 00 e7 00 30 00 30 00 e7 00 30 00 e7 00 38 00 42 00 37 00 e7 00 36 00 e7 00 30 00 43 00 e7 00 38 00 e7 00 42 00 37 00 e7 00 36 00 e7 00 30 00 43 00 e7 00 38 00 42}  //weight: 1, accuracy: High
        $x_1_2 = {00 38 00 42 00 e7 00 34 00 e7 00 34 00 33 00 38 00 e7 00 37 00 38 00 e7 00 30 00 e7 00 33 00 43 00 37 00 38 00 42 00 35 00 e7 00 30 00 32 00 30 00 e7 00 38 00 e7 00 42 00 e7 00 35 00 e7}  //weight: 1, accuracy: High
        $x_1_3 = {00 33 00 e7 00 43 00 37 00 e7 00 38 00 35 00 e7 00 37 00 30 00 46 00 e7 00 46 00 46 00 e7 00 46 00 46 00 e7 00 46 00 39 00 39 00 e7 00 42 00 30 00 e7 00 34 00 e7 00 38 00 e7 00 30 00 e7 00 36}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_AutInject_CZ_2147735223_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.CZ!bit"
        threat_id = "2147735223"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$URL , $FILENAME , $DIR" wide //weight: 10
        $x_10_2 = "$URLOPEN , $VBSOPEN , $OPENFILE , $HFILE" wide //weight: 10
        $x_10_3 = "$FILE , $REGKEY , $ATTRIB , $HIDDEN" wide //weight: 10
        $x_10_4 = "$FILE , $STARTUP , $RES" wide //weight: 10
        $x_10_5 = "$RESNAME , $RESTYPE" wide //weight: 10
        $x_10_6 = "$WPATH , $WARGUMENTS , $LPFILE , $PROTECT" wide //weight: 10
        $x_10_7 = "$WPATH , $LPFILE , $PROTECT , $PERSIST" wide //weight: 10
        $x_10_8 = "$VDATA , $VCRYPTKEY" wide //weight: 10
        $x_10_9 = "SLEEP ( $TIME / $LOOP" wide //weight: 10
        $x_1_10 = "REMOVEZONEID" wide //weight: 1
        $x_1_11 = "STRINGREPLACE ( $STEXT , $SYMBOL , \"\"" wide //weight: 1
        $x_1_12 = "STRINGSPLIT ( $STR , \",\"" wide //weight: 1
        $x_1_13 = "$BIN_SHELLCODE &=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_AutInject_SM_2147739789_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.SM!bit"
        threat_id = "2147739789"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "STRINGREVERSE ( \"exe.dslootmv\" ) )" wide //weight: 1
        $x_1_2 = "STRINGREVERSE ( \"dnammoc\\nepo\\llehs\\elifcsm\\sessalC\\erawtfoS\\UCKH\" )" wide //weight: 1
        $x_1_3 = "STRINGREVERSE ( \"lld.23lenrek\" )" wide //weight: 1
        $x_1_4 = "$BIN_SHELLCODE &=" wide //weight: 1
        $x_1_5 = "@HOMEDRIVE & \"\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\RegSvcs.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_AutInject_DB_2147740308_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.DB!bit"
        threat_id = "2147740308"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RETURN EXECUTE ( \"StringSplit\" )" wide //weight: 1
        $x_1_2 = "RETURN EXECUTE ( \"StringLen\" )" wide //weight: 1
        $x_1_3 = "FOR $I = \"1\" TO $SPLIT [ \"0\" ]" wide //weight: 1
        $x_1_4 = "$RESULT &= CHRW ( $XOR )" wide //weight: 1
        $x_1_5 = "$BIN_SHELLCODE &=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_AutInject_DD_2147740309_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/AutInject.DD!bit"
        threat_id = "2147740309"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AutInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OPT ( ELRMJNYDTSUC ( \"0x5771627A4A606C6D4B6A6766\" , \"0x464E71\" ) , ELRMJNYDTSUC ( \"0x33\" , \"0x4D77\" ) )" wide //weight: 1
        $x_1_2 = "LOCAL $B = $EXEC ( ELRMJNYDTSUC ( \"0x666D6A65767D706B7770766D6A63\" , \"0x71677278\" ) )" wide //weight: 1
        $x_1_3 = "LOCAL $EXEC = EXECUTE" wide //weight: 1
        $x_1_4 = "FUNC RUNPE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

