rule Worm_Win32_Delf_AZ_2147595963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Delf.AZ"
        threat_id = "2147595963"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "137"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_10_2 = "<?php @eval($_POST[jokeyouphp])?>" ascii //weight: 10
        $x_10_3 = "<%execute request(\"jokeyou\")&\"\"%>" ascii //weight: 10
        $x_10_4 = "<script language=\"javascript\" src=\"http://htmlcss.3322.org/sub/ray.js\"></script>" ascii //weight: 10
        $x_1_5 = ":\\autorun.inf" ascii //weight: 1
        $x_1_6 = ":\\RECYCLER.exe" ascii //weight: 1
        $x_1_7 = "Update.exe" ascii //weight: 1
        $x_1_8 = "Upgrade.exe" ascii //weight: 1
        $x_1_9 = "open=RECYCLER.exe" ascii //weight: 1
        $x_1_10 = "shellexecute=RECYCLER.exe" ascii //weight: 1
        $x_1_11 = "shell\\Auto\\command=RECYCLER.exe" ascii //weight: 1
        $x_1_12 = "MONSYSNT.EXE" ascii //weight: 1
        $x_1_13 = "SPIDERNT.EXE" ascii //weight: 1
        $x_1_14 = "ICESWORD.EXE" ascii //weight: 1
        $x_1_15 = "NET STOP OfficeScanNT Monitor" ascii //weight: 1
        $x_1_16 = "NET STOP Norton" ascii //weight: 1
        $x_1_17 = "NET STOP ZoneAlarm" ascii //weight: 1
        $x_1_18 = "NET stop Symantec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Delf_BA_2147596912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Delf.BA"
        threat_id = "2147596912"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "105"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "Kill Process <" ascii //weight: 10
        $x_10_3 = "Delete file <" ascii //weight: 10
        $x_10_4 = "[autorun]" ascii //weight: 10
        $x_10_5 = "shellexecute = antihost.exe" ascii //weight: 10
        $x_10_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_7 = "ShellExecuteA" ascii //weight: 10
        $x_10_8 = "SetWindowsHookExA" ascii //weight: 10
        $x_10_9 = "UnhookWindowsHookEx" ascii //weight: 10
        $x_10_10 = "Toolhelp32ReadProcessMemory" ascii //weight: 10
        $x_1_11 = "ahr.exe" ascii //weight: 1
        $x_1_12 = "autorun.inf" ascii //weight: 1
        $x_1_13 = ":\\autorun.inf" ascii //weight: 1
        $x_1_14 = ":\\temp1.exe" ascii //weight: 1
        $x_1_15 = ":\\copy.exe" ascii //weight: 1
        $x_1_16 = ":\\host.exe" ascii //weight: 1
        $x_1_17 = ":\\antihost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Delf_BB_2147601669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Delf.BB"
        threat_id = "2147601669"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "71"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {84 c0 75 33 6a 00 68 ?? ?? 45 00 8d 55 d8 a1 e8 40 45 00 8b 00 e8 ?? ?? ?? ff 8b 45 d8 e8 ?? ?? ?? ff 50 e8 ?? ?? ?? ff ba 05 00 00 00 b8 ?? ?? 45 00 e8 ?? ?? ?? ff b8 ?? ?? 45 00 e8 08 f8 ff ff 84 c0 0f 84 a5 00 00 00 8d 45 f0 ba 78 1d 45 00 e8 ?? ?? ?? ff b2 01 a1 74 71 42 00 e8 ?? ?? ?? ff 89 45 f4 33 c0 55 68 ?? ?? 45 00 64 ff 30 64 89 20 8d 45 f8}  //weight: 10, accuracy: Low
        $x_10_2 = {84 c0 75 67 6a 00 8d 85 d8 fe ff ff b9 ?? ?? 45 00 8b 55 fc e8 ?? ?? fb ff 8b 85 d8 fe ff ff e8 ?? ?? fb ff 50 8d 95 d4 fe ff ff a1 ?? ?? 45 00 8b 00 e8 ?? ?? ?? ?? 8b 85 d4 fe ff ff e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8d 85 d0 fe ff ff b9 ?? ?? 45 00 8b 55 fc e8 ?? ?? ?? ?? 8b 85 d0 fe ff ff ba 07 00 00 00 e8 ?? ?? ?? ?? 8d 85 cc fe ff ff b9 ?? ?? 45 00 8b 55 fc}  //weight: 10, accuracy: Low
        $x_10_3 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_4 = ":\\autorun.inf" ascii //weight: 10
        $x_10_5 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_6 = "Menu Iniciar\\Programas\\Inicializar\\winsys2.exe" ascii //weight: 10
        $x_10_7 = ":\\winsys2.exe" ascii //weight: 10
        $x_1_8 = "C:\\WINDOWS\\setup.ini" ascii //weight: 1
        $x_1_9 = "http://seguritysys.kinghost.net/?id=1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Delf_BC_2147602087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Delf.BC"
        threat_id = "2147602087"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "53"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "WSARecvEx" ascii //weight: 10
        $x_10_2 = "TransmitFile" ascii //weight: 10
        $x_10_3 = "Aclomerlog@gmail.com" ascii //weight: 10
        $x_10_4 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_5 = "Logs y capturas vienen adjuntados" ascii //weight: 10
        $x_1_6 = "%sysdir%" ascii //weight: 1
        $x_1_7 = "msky\\logs\\kyl*" ascii //weight: 1
        $x_1_8 = "msky\\clickshots\\kyc*" ascii //weight: 1
        $x_1_9 = "/lanzateRunOnce" ascii //weight: 1
        $x_1_10 = "InternetConnectA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Delf_ZAB_2147603247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Delf.ZAB"
        threat_id = "2147603247"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "autent.jpg" ascii //weight: 1
        $x_1_2 = "http://geocities.yahoo.com.br/youtoba03/listaaut.jpg" ascii //weight: 1
        $x_1_3 = "http://www.gratisweb.com/vaisefuder00" ascii //weight: 1
        $x_1_4 = "http://www.youtoba01.hpg.com.br" ascii //weight: 1
        $x_1_5 = "infver.txt" ascii //weight: 1
        $x_1_6 = "versao.jpg" ascii //weight: 1
        $x_1_7 = "diskdrive.exe" ascii //weight: 1
        $x_1_8 = "links.jpg" ascii //weight: 1
        $x_1_9 = "inf.jpg" ascii //weight: 1
        $x_1_10 = "inf.txt" ascii //weight: 1
        $x_1_11 = "autorun.inf" ascii //weight: 1
        $x_1_12 = "shell\\open\\command=diskdrive.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Delf_BD_2147612797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Delf.BD"
        threat_id = "2147612797"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "76"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 10
        $x_10_2 = "Sexy Girls.scr" ascii //weight: 10
        $x_10_3 = "Optimizer.pif" ascii //weight: 10
        $x_10_4 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_5 = "FrameWorkService" ascii //weight: 10
        $x_10_6 = "::{450D8FBA-AD25-11D0-98A8-0800361B1103}" ascii //weight: 10
        $x_10_7 = "_Fichiers.exe" ascii //weight: 10
        $x_1_8 = "mmc.exe" ascii //weight: 1
        $x_1_9 = "rstrui.exe" ascii //weight: 1
        $x_1_10 = "regedit.exe" ascii //weight: 1
        $x_1_11 = "regedt32.exe" ascii //weight: 1
        $x_1_12 = "NoFolderOptions" ascii //weight: 1
        $x_1_13 = "NoRun" ascii //weight: 1
        $x_1_14 = "NoFind" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Delf_BT_2147614413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Delf.BT"
        threat_id = "2147614413"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Software\\Borland\\Delphi" ascii //weight: 10
        $x_10_2 = "[autorun]" ascii //weight: 10
        $x_10_3 = "Software\\Microsoft\\Internet Explorer\\Typed" ascii //weight: 10
        $x_10_4 = {52 45 47 20 41 44 44 20 48 4b 45 59 5f [0-16] 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76}  //weight: 10, accuracy: Low
        $x_1_5 = "open=RECYCLER\\autoplay.exe" ascii //weight: 1
        $x_1_6 = "shell\\open\\Command=RECYCLER\\autoplay.exe" ascii //weight: 1
        $x_1_7 = "shell\\explore\\Command=RECYCLER\\autoplay.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Delf_BE_2147621647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Delf.BE"
        threat_id = "2147621647"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "-port 80 -insert \"<iframe border=\"0\" framespacing=\"0\" frameborder=\"0\" scrolling=\"no\" width=\"0\" height=\"0\" src=\"" ascii //weight: 10
        $x_10_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\ShellExecuteHooks" ascii //weight: 10
        $x_10_4 = "Autorun.inf" ascii //weight: 10
        $x_1_5 = "drivers\\npf.sys" ascii //weight: 1
        $x_1_6 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
        $x_1_7 = "WindowsXP.exe" ascii //weight: 1
        $x_1_8 = "EnableFirewall" ascii //weight: 1
        $x_1_9 = "{A781A1EC-975E-4788-AF8E-A3F552D55C41}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Delf_BE_2147829048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Delf.BE!MTB"
        threat_id = "2147829048"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ADAC Routenplaner 2005-2006_keygen.exe" ascii //weight: 1
        $x_1_2 = "Age Of Mythology no cd crack.exe" ascii //weight: 1
        $x_1_3 = "Empire_At_War_NOCD_Crack.exe" ascii //weight: 1
        $x_1_4 = "F.E.A.R CD and EXE Crack+keygen.exe" ascii //weight: 1
        $x_1_5 = "Animation Workshop KeyGen.exe" ascii //weight: 1
        $x_1_6 = "Harry Potter and The Sorcerers Stone no cd crack.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

