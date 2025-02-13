rule TrojanDropper_Win32_Bancos_A_2147627858_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bancos.A"
        threat_id = "2147627858"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 d8 8d 45 dc b9 00 00 00 00 e8 ?? ?? fa ff 8b 45 dc e8 ?? ?? fa ff 50 e8 ?? ?? fa ff 8d 45 d4 50 8b cb ba ?? ?? ?? ?? 8b c6}  //weight: 10, accuracy: Low
        $x_1_2 = "DADOSECOND=OK" wide //weight: 1
        $x_1_3 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bancos_B_2147628516_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bancos.B"
        threat_id = "2147628516"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Builds\\TP\\indysockets\\lib\\Protocols\\IdSSLOpenSSL.pas" wide //weight: 1
        $x_1_2 = "\\price.zip" wide //weight: 1
        $x_1_3 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "http://lifestyle.inovalink.net/dexter/expert.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bancos_XP_2147640631_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bancos.XP"
        threat_id = "2147640631"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0f b6 74 10 ff 8b c7 c1 e0 08 03 f0 8b fe 83 c3 08 83 fb 06 7c 4d}  //weight: 3, accuracy: High
        $x_1_2 = "If exist \"%s\" Goto 1" ascii //weight: 1
        $x_1_3 = "uptime.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Bancos_G_2147645826_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bancos.G"
        threat_id = "2147645826"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Windows Live Help\\cssrss.exe" ascii //weight: 1
        $x_1_2 = {5c 57 69 6e 64 6f 77 73 20 4d 65 64 69 61 20 50 6c 61 79 65 72 5c [0-5] 6c 76 6d 78 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "Copyright (c) 1999,2003 Avenger by NhT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bancos_J_2147651313_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bancos.J"
        threat_id = "2147651313"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c f8 00 00 73 65 78 6f 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 43 00 3a 00 5c 00 49 00 6e 00 63 00 6c 00 75 00 64 00 65 00 5c 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {a3 48 4b be 98 6c 4a a9 99 4c 53 0a 86 d6 48 7d 66 6f 6f 6c 44 37 39 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5e 6f fe 78 af ad 00 00 e6 fb 25 78 c8 e2 13 f9 7d 1d ed dd 71 00 b0 55 2d ac 9a d5 28 15 d4 f0 cf 25 e4 cf 11 8e 56 c2 ce 3f 70 ef b9 68 0c f8 00 00 06 50 c5 71 70 8e 4a 74 2e 3a df a5 ef 68 29 bc d2 9b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bancos_L_2147652060_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bancos.L"
        threat_id = "2147652060"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\tudo zero\\PRONTO\\vetim_load_vb\\" wide //weight: 2
        $x_1_2 = "\\system32\\regsvr32.exe /s lisa.dll" wide //weight: 1
        $x_1_3 = "\\system32\\regsvr32.exe /s sm.dll" wide //weight: 1
        $x_1_4 = "\\system32\\GetDiskSerial.dll" wide //weight: 1
        $x_1_5 = "\\system32\\amd.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

