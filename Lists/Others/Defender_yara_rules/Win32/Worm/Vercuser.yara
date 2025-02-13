rule Worm_Win32_Vercuser_A_2147679862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vercuser.A"
        threat_id = "2147679862"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vercuser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "160"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "h2s(\"5B6175746F72756E5D0A5573654175746F506C61793D31" ascii //weight: 50
        $x_50_2 = "657865637574653D5553425C446174615C53656375726544726976652E65786520" ascii //weight: 50
        $x_50_3 = "686b37047e506a00e85ef5ffff6a006a00ffd0888533f9ffff680e03e5e6" ascii //weight: 50
        $x_50_4 = "ff37ffb6c30a000050ff96dd0000000fb7570489043283c706ebe0688fd8a4bb" ascii //weight: 50
        $x_10_5 = "h2s(\"636F6E6E656B746D652E686F70746F2E6F72673A373533397C636F6E6E" ascii //weight: 10
        $x_10_6 = "67736572766572686F73742E6D796674702E6F72673A353535357C6773657276" ascii //weight: 10
        $x_10_7 = "asd.exe,\\adware_pro.exe,\\akm" ascii //weight: 10
        $x_10_8 = "~temp~clear~[0-9]{5}\\.exe$\")" ascii //weight: 10
        $x_10_9 = "USB\\Data\\SecureDrive.exe" wide //weight: 10
        $x_10_10 = {50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 00 00 00 00 2c 00 00 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 41 00 75 00 74 00 6f 00 44 00 72 00 69 00 76 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: High
        $x_5_11 = "FED2AEDF8471048640B780BAAC690F78" ascii //weight: 5
        $x_5_12 = "D0B914074366980EC26D76B032784E50" ascii //weight: 5
        $x_5_13 = "zinaps7.exe,\\~.exe,antivirus\\treav.exe" ascii //weight: 5
        $x_5_14 = "%TsDv%\\Passwords.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 4 of ($x_10_*) and 4 of ($x_5_*))) or
            ((2 of ($x_50_*) and 5 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_50_*) and 6 of ($x_10_*))) or
            ((3 of ($x_50_*) and 2 of ($x_5_*))) or
            ((3 of ($x_50_*) and 1 of ($x_10_*))) or
            ((4 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Vercuser_B_2147679964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vercuser.B"
        threat_id = "2147679964"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vercuser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kill_del(, TsDrv \"\\System\\AutoDrive.exe\")" ascii //weight: 1
        $x_1_2 = "kill_del(, startup \"\\Internet Security.lnk\")" ascii //weight: 1
        $x_1_3 = "Task Manager ahk_class AnVirMainFrame" ascii //weight: 1
        $x_1_4 = "kill_del(, myprg_dir \"\\Windows Defender" ascii //weight: 1
        $x_1_5 = "kill_del(, a_loopfield \":\\autorun.inf\")" ascii //weight: 1
        $x_1_6 = "\\000b09274b.exe,\\0cf48.exe,\\61a60\\we83b.exe,\\a-fast.exe,\\amvo.exe,\\ab\\abest.exe," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Worm_Win32_Vercuser_C_2147679966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vercuser.C"
        threat_id = "2147679966"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vercuser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%TsDv%\\autorun.inf" ascii //weight: 1
        $x_1_2 = "[autorun]ACTION=Open USB Driveopen=" ascii //weight: 1
        $x_1_3 = "filesetattrib, +RASH, %TsDv%\\autorun.inf" ascii //weight: 1
        $x_1_4 = "DriveGet, RmDrvs, list, REMOVABLE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vercuser_D_2147681708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vercuser.D"
        threat_id = "2147681708"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vercuser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "310"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "(BE|KB)\\.tmp\\.(exe|[0-9]{1,2}\\.exe)" ascii //weight: 100
        $x_100_2 = "|temp~manager\\.exe|ServicesStarter\\.exe$" ascii //weight: 100
        $x_50_3 = "A_UserName,\"drwebstatic.hopto.org" ascii //weight: 50
        $x_50_4 = "3OvjxKyihKPNntC8r6iutZG7orjb6t" ascii //weight: 50
        $x_50_5 = "\"woTrsU0l8kEN6IBcY6It\")" ascii //weight: 50
        $x_50_6 = "delete, %startup%\\Secure Web.lnk" ascii //weight: 50
        $x_50_7 = "a_scriptname != \"temp~manager.exe\"" ascii //weight: 50
        $x_10_8 = "%file_mov_dir%\\~DF%nnn%KB.tmp.exe" ascii //weight: 10
        $x_10_9 = "40636C69656E742433323124" ascii //weight: 10
        $x_20_10 = "%atemp%\\~temp~%ayday%~.tmp" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 4 of ($x_50_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 4 of ($x_50_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 5 of ($x_50_*))) or
            ((2 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_10_*))) or
            ((2 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_20_*))) or
            ((2 of ($x_100_*) and 3 of ($x_50_*))) or
            (all of ($x*))
        )
}

