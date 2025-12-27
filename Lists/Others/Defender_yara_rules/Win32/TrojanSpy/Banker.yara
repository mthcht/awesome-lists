rule TrojanSpy_Win32_Banker_P_2147506052_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.P"
        threat_id = "2147506052"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {40 89 c7 8d b3 ?? ?? ?? ?? 8b c3 b9 26 00 00 00 99 f7 f9 8b 45 ?? 8a 14 10 32 16}  //weight: 4, accuracy: Low
        $x_3_2 = {8a 18 80 f3 ?? 88 1a 42 40 49 75 f4}  //weight: 3, accuracy: Low
        $x_1_3 = {2c 5b 5f 10 00 15 14 0c 40 02 58 35}  //weight: 1, accuracy: High
        $x_1_4 = {06 1a 01 0c 03 53 3e 3a 55 22 17 11 1c 1b 05 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_Q_2147506055_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.Q"
        threat_id = "2147506055"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 0b 83 c3 04 8b 32 83 c2 04 f3 a4 48 75 f1}  //weight: 3, accuracy: High
        $x_1_2 = "netview.exe" ascii //weight: 1
        $x_1_3 = "360netview.dll" ascii //weight: 1
        $x_1_4 = "360Safe.exe" ascii //weight: 1
        $x_1_5 = "CreateCnntView" ascii //weight: 1
        $x_1_6 = "rsion\\Run\\ShellRun" ascii //weight: 1
        $x_1_7 = ".anti" ascii //weight: 1
        $x_1_8 = "fuckyou" ascii //weight: 1
        $x_1_9 = "&password=" ascii //weight: 1
        $x_1_10 = "&money=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_DE_2147551209_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.DE"
        threat_id = "2147551209"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "402"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SVCHOST" wide //weight: 100
        $x_100_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_100_3 = "Sistema operacional Microsoft" wide //weight: 100
        $x_100_4 = "Microsoft Corporation. Todos os direitos reservados." wide //weight: 100
        $x_1_5 = "MAIL FROM:<" ascii //weight: 1
        $x_1_6 = "u_Princ_2606" ascii //weight: 1
        $x_1_7 = "E m P r E s A s . N E T" ascii //weight: 1
        $x_1_8 = "{ I n f . N E T E m p r e s a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_DQ_2147551213_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.DQ"
        threat_id = "2147551213"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2000"
        strings_accuracy = "Low"
    strings:
        $x_1000_1 = {c6 00 30 a1 ?? ?? 48 00 ba ?? ?? 47 00 e8 ?? ?? f8 ff e8 ?? ?? f9 ff dd 1d ?? ?? 48 00 9b ff 35 ?? ?? 48 00 ff 35 ?? ?? 48 00 8d 45 fc e8 ?? ?? f9 ff 8b 55 fc b8 ?? ?? 48 00 e8 ?? ?? f8 ff 68 ?? ?? 47 00 ff 35 ?? ?? 48 00 68 ?? ?? 47 00 8d 45 f8 ba 03 00 00 00 e8 ?? ?? f8 ff 8b 45 f8}  //weight: 1000, accuracy: Low
        $x_1000_2 = {33 d2 8b 83 ?? 04 00 00 e8 ?? ?? fb ff e9 ?? ?? 00 00 e8 ?? ?? f9 ff d8 25 ?? ?? 47 00 dd 1d ?? ?? 48 00 9b ff 35 ?? ?? 48 00 ff 35 ?? ?? 48 00 8d 45 f4 e8 ?? ?? f9 ff 8b 55 f4 b8 ?? ?? 48 00 e8 ?? ?? f8 ff 68 ?? ?? 47 00 ff 35 ?? ?? 48 00 68 ?? ?? 47 00 8d 45 f0 ba 03 00 00 00}  //weight: 1000, accuracy: Low
        $x_100_3 = "winlog" ascii //weight: 100
        $x_100_4 = "msbcb.exe" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1000_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_DR_2147551214_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.DR"
        threat_id = "2147551214"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\CEF\\VBBHO.vbp" wide //weight: 10
        $x_10_2 = "gbiehcef.dll" ascii //weight: 10
        $x_10_3 = "Shdocwv.dll" ascii //weight: 10
        $x_5_4 = "Scpad.exe" wide //weight: 5
        $x_5_5 = "https://internetbanking.caixa.gov.br/SIIBC/index" wide //weight: 5
        $x_1_6 = "msvbvm60.dll" ascii //weight: 1
        $x_1_7 = "zombie_gettypeinfocount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_ND_2147564852_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ND"
        threat_id = "2147564852"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "<keystorefile KEYFILE=" ascii //weight: 2
        $x_1_2 = "userinit.exe,sv" ascii //weight: 1
        $x_1_3 = "https://ibank." ascii //weight: 1
        $x_1_4 = "update.php?os=" ascii //weight: 1
        $x_1_5 = "cmd.exe /k echo y| cacls" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_A_2147574812_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.gen!A"
        threat_id = "2147574812"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8d 55 ec b8 b8 2f 41 00 e8 c2 fa ff ff 8b 45 ec e8 72 11 ff ff 50 6a 00 6a 00 e8 c4 2a ff ff e8 5f 2b ff ff 85 c0 0f 85 f4 02 00 00 be 01 00 00 00 8d 45 e4 e8 ca fb ff ff ff 75 e4 68 c8 2f 41 00 8d 55 e0 b8 d4 2f 41 00 e8 81 fa ff ff ff 75 e0 8d 45 e8 ba 03 00 00 00 e8 e9 0f ff ff 8b 45 e8 e8 09 43 ff ff}  //weight: 5, accuracy: High
        $x_5_2 = {7e 29 bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 83 ea 0f e8 b5 13 ff ff 8b 55 f4 8d 45 f8 e8 66 14 ff ff 43 4e 75 dc 8b c7 8b 55 f8 e8 08 12 ff ff 33 c0 5a 59 59 64 89 10 68 ba 27 41 00 8d 45 f4 ba 03 00 00 00 e8 be 11 ff ff c3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_USW_2147596425_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.USW"
        threat_id = "2147596425"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@gmail.com" ascii //weight: 1
        $x_1_2 = " - Microsoft Internet Explore" ascii //weight: 1
        $x_1_3 = " - Mozilla Firefox" ascii //weight: 1
        $x_1_4 = {55 8b ec 83 c4 e8 53 56 57 33 db 89 5d e8 89 5d ec 89 4d f8 89 55 fc 8b 45 fc e8 11 1b f8 ff 33 c0 55 68}  //weight: 1, accuracy: High
        $x_1_5 = {53 32 48 00 64 ff 30 64 89 20 8b 45 f8 e8 4b 16 f8 ff 33 ff 33 c0 89 45 f0 8b 45 fc e8 fc 18 f8 ff 8b f0}  //weight: 1, accuracy: High
        $x_1_6 = {85 f6 0f 8e 92 00 00 00 c7 45 f4 01 00 00 00 8d 45 ec 8b 55 fc 8b 4d f4 8a 54 0a ff e8 01 18 f8 ff 8b 45}  //weight: 1, accuracy: High
        $x_1_7 = {ec ba 6c 32 48 00 e8 10 1c f8 ff 8b d8 4b 85 db 7c 65 8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08}  //weight: 1, accuracy: High
        $x_1_8 = {7c 48 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81}  //weight: 1, accuracy: High
        $x_1_9 = {e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 8d 45 e8 8b d3 e8 a0 17 f8 ff 8b 55 e8 8b 45 f8 e8 75 18 f8}  //weight: 1, accuracy: High
        $x_1_10 = {ff 8b 45 f8 ff 45 f4 4e 0f 85 75 ff ff ff 33 c0 5a 59 59 64 89 10 68 5a 32 48 00 8d 45 e8 ba 02 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {e8 aa 15 f8 ff 8d 45 fc e8 7e 15 f8 ff c3 e9 f8 0e f8 ff eb e3 5f 5e 5b 8b e5 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule TrojanSpy_Win32_Banker_CVD_2147596442_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.CVD"
        threat_id = "2147596442"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WinExec" ascii //weight: 1
        $x_1_2 = "gethostbyname" ascii //weight: 1
        $x_5_3 = {8d 95 e4 fe ff ff 8d 85 fc fe ff ff e8 ?? ?? ?? ?? 8b 95 e4 fe ff ff 8d 83 14 03 00 00 e8 ?? ?? ?? ?? 8d 95 e0 fe ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 85 e0 fe ff ff e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 85 c0 76 3b 6a 00 6a 00 6a 10 8d 95 dc fe ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 85 dc fe ff ff e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? a1 f0 1a 4f 00 8b 00 e8 ?? ?? ?? ?? 8d 95 d8 fe ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 85 d8 fe ff ff e8 ?? ?? ?? ?? 50 8b 83 14 03 00 00 e8 ?? ?? ?? ?? 5a e8 ?? ?? ?? ?? 85 c0 0f 84 b7 00 00 00 8d 95 d0 fe ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 85 d0 fe ff ff e8 ?? ?? ?? ?? 8b d0 8d 85 d4 fe ff ff}  //weight: 5, accuracy: Low
        $x_5_4 = {42 74 54 74 54 6f 76 70 4f 4d 76 71 4f 4d 76 61 50 4e 38 6b 4f 73 7a 6a 42 63 39 6f 42 74 31 6c 53 64 48 58 52 32 7a 64 53 73 38 6c 53 73 44 6f 51 4e 31 71 42 74 48 62 52 4e 31 69 4f 4e 48 62 53 6f 7a 37 47 71 72 49 50 4e 35 72 50 4e 44 71 42 63 48 6c 46 74 31 58 50 73 4b 7a 44 4a 30 00 ff ff ff ff 4c 00 00 00 51 37 48 71 53 37 43 77 42 6f 7a 66 52 64 48 62 53 63 76 62 54 36 39 58 52 63 6a 66 52 63 53 6b 4f 73 35 66 55 36 34 6b 50 73 7a 73 42 63 39 6f 42 72 44 39 49 4b 39 33 42 73 62 6b 50 36 4c 75 42 64 31 6f 52 73 44 62 53 74 44 58 00 00 00 00 ff ff ff ff 14 00 00 00 47 73 35 66 55 36 34 57 48 4d 44 6c 52 63 7a 6a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_B_2147596643_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.gen!B"
        threat_id = "2147596643"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "\\legoz\\nlhtml" ascii //weight: 4
        $x_1_2 = {26 64 61 74 61 5f 74 79 70 65 3d 64 6c ?? 26 64 61 74 61 5f 63 6f 6e 74 65 6e 74 3d}  //weight: 1, accuracy: Low
        $x_1_3 = "&check=aWsEdR" ascii //weight: 1
        $x_1_4 = "\\Implemented Categories" ascii //weight: 1
        $x_1_5 = "\\Required Categories" ascii //weight: 1
        $x_1_6 = "Module_Raw" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_VH_2147596742_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VH"
        threat_id = "2147596742"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "finanzportal.fiducia.de" ascii //weight: 1
        $x_1_2 = "internetsube.akbank.com.tr" ascii //weight: 1
        $x_1_3 = "bankofamerica" ascii //weight: 1
        $x_1_4 = "CLICKS=%s" ascii //weight: 1
        $x_1_5 = "yapikredi.com.tr" ascii //weight: 1
        $x_1_6 = "%s=KEYLOGGED:%s KEYSREAD:%s" ascii //weight: 1
        $x_1_7 = "password" ascii //weight: 1
        $x_1_8 = "IE Auto Complete Fields" ascii //weight: 1
        $x_1_9 = "IE:Password-Protected sites" ascii //weight: 1
        $x_1_10 = "Deleted OE Account" ascii //weight: 1
        $x_1_11 = "/upload.php" ascii //weight: 1
        $x_1_12 = "/mail.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_VI_2147596843_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VI"
        threat_id = "2147596843"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ep_account_no" ascii //weight: 1
        $x_1_2 = "ep_password" ascii //weight: 1
        $x_1_3 = "_KG\\0.bmp" ascii //weight: 1
        $x_1_4 = "/Count.asp?mac=" ascii //weight: 1
        $x_1_5 = "http://110.34.232.11:1314" ascii //weight: 1
        $x_1_6 = "INIdirectbankUI60.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Banker_DES_2147597289_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.DES"
        threat_id = "2147597289"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "56"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "simcard1.dll" ascii //weight: 10
        $x_10_2 = "ppret2.dll" ascii //weight: 10
        $x_10_3 = "tns1.dll" ascii //weight: 10
        $x_10_4 = "68D5BBF9-EED5-4125-B227-55F81540BF4D" ascii //weight: 10
        $x_10_5 = "A47E5EA5-F34F-41e9-8C28-860BA09DF8D9" ascii //weight: 10
        $x_5_6 = "Software\\MRSoft" ascii //weight: 5
        $x_1_7 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_USY_2147598151_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.USY"
        threat_id = "2147598151"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "T65pQsjfR6mWBsOWBsbj84T2K5DMBaLOHG" ascii //weight: 1
        $x_1_2 = "T65pQsjfR6mWBsOWBsbj84j1Lb16BcLuPG" ascii //weight: 1
        $x_1_3 = "T65pQsjfR6mWBsOWBsbj84jXTYvbU6K" ascii //weight: 1
        $x_1_4 = "T65pQsjfR6mWBsOWBsbj86rZP65pQ2vbU6K" ascii //weight: 1
        $x_1_5 = "T65pQsjfR6mWBsOWBsbj84rZP6LqPMDqBcLuPG" ascii //weight: 1
        $x_1_6 = "T65pQsjfR6mWBsOWBsbj86rZScLdTsbwBcLuPG" ascii //weight: 1
        $x_1_7 = "T65pQsjfR6mWBsOWBsbj84rZL7DhSsXaBcLuPG" ascii //weight: 1
        $x_1_8 = "T65pQsjfR6mWBsOWBsbj86rZTN1aRMToBcLuPG" ascii //weight: 1
        $x_1_9 = "T65pQsjfR6mWBsOWBsbj86rZTN1aTMakPNXb" ascii //weight: 1
        $x_1_10 = "T65pQsjfR6mWBsOWBsbj84rmPa5dPMvqBcLuPG" ascii //weight: 1
        $x_1_11 = "T65pQsjfR6mWBsOWBsbj84rmPaDlRdDlR6KkPNXb" ascii //weight: 1
        $x_1_12 = "T65pQsjfR6mWBsOWBsbj84rmPbDbSdPfOsKkPNXb" ascii //weight: 1
        $x_1_13 = "T65pQsjfR6mWBsOWBsbj84rmPbHoONakPNXb" ascii //weight: 1
        $x_1_14 = "T65pQsjfR6mWBsOWBsbj84rmPbTfUc5oP2vbU6K" ascii //weight: 1
        $x_1_15 = "T65pQsjfR6mWBsOWBsbj86rsT7WkPNXb" ascii //weight: 1
        $x_1_16 = "T65pQsjfR6mWBsOWBsbj86rZON1mQMvpBcLuPG" ascii //weight: 1
        $x_1_17 = "T65pQsjfR6mWBsOWBsbj86rZQMvcRovbU6K" ascii //weight: 1
        $x_1_18 = "T65pQsjfR6mWBsOWBsbj86rdQ7HjR2vbU6K" ascii //weight: 1
        $x_1_19 = "T65pQsjfR6mWBsOWBsbj86rZQMvpTN1aBcLuPG" ascii //weight: 1
        $x_1_20 = "T65pQsjfR6mWBsOWBsbj86rZRMveP6noBcLuPG" ascii //weight: 1
        $x_1_21 = "T65pQsjfR6mWBsOWBsbj84rZKsXfPMnaBcLuPG" ascii //weight: 1
        $x_1_22 = "T65pQsjfR6mWBsOWBsbj84rZLbD5SsDkBcLuPG" ascii //weight: 1
        $x_1_23 = "T65pQsjfR6mWBsOWBsbj86rZTdDcT7DkBcLuPG" ascii //weight: 1
        $x_1_24 = "T65pQsjfR6mWBsOWBsbj86rZTdDjON0kPNXb" ascii //weight: 1
        $x_1_25 = "T65pQsjfR6mWBsOWBsbj86vXQM5sPcbkBcLuPG" ascii //weight: 1
        $x_1_26 = "T65pQsjfR6mWBsOWBsbj86zXSsDiRdGkPNXb" ascii //weight: 1
        $x_1_27 = "T65pQsjfR6mWBsOWBsbj86TZONDJPN9sBcLuPG" ascii //weight: 1
        $x_1_28 = "T65pQsjfR6mWBsOWBsbj87fiOsnfPMvqBcLuPG" ascii //weight: 1
        $x_1_29 = "T65pQsjfR6mWBsOWBsbj865sPsLjOovbU6K" ascii //weight: 1
        $x_1_30 = "T65pQsjfR6mWBsOWBsbj865sPtLmStPZBcLuPG" ascii //weight: 1
        $x_1_31 = "T65pQsjfR6mWBsOWBsbj865sPs5jStPoBcLuPG" ascii //weight: 1
        $x_1_32 = "T65pQsjfR6mWBsOWBsbj865sPsDZBcLuPG" ascii //weight: 1
        $x_1_33 = "T65pQsjfR6mWBsOWBsbj865pQ6HfSt0kPNXb" ascii //weight: 1
        $x_1_34 = "T65pQsjfR6mWBsOWBsbj865pQ6rXQNDsBcLuPG" ascii //weight: 1
        $x_1_35 = "T65pQsjfR6mWBsOWBsbj865pQ7DbSdOkPNXb" ascii //weight: 1
        $x_1_36 = "T65pQsjfR6mWBsOWBsbj865pQ7TbOdDsBcLuPG" ascii //weight: 1
        $x_1_37 = "T65pQsjfR6mWBsOWBsbj865pTtLmP7DsBcLuPG" ascii //weight: 1
        $x_1_38 = "T65pQsjfR6mWBsOWBsbj86DZSsLqRMToBcLuPG" ascii //weight: 1
        $x_1_39 = "T65pQsjfR6mWBsOWBsbj86DZOt1oRtXvBcLuPG" ascii //weight: 1
        $x_1_40 = "T65pQsjfR6mWBsOWBsbj86DZON1mBcLuPG" ascii //weight: 1
        $x_1_41 = "T65pQsjfR6mWBsOWBsbj86DZPNPqRMToBcLuPG" ascii //weight: 1
        $x_1_42 = "T65pQsjfR6mWBsOWBsbj86vlP3CoQt9kBcLuPG" ascii //weight: 1
        $x_1_43 = "T65pQsjfR6mWBsOWBsbj86vlP3CoQtLfBcLuPG" ascii //weight: 1
        $x_1_44 = "N5DlPdHtON9bN4rfOt9lSszcT5nNQMvaRtTpN4DrSd9bRdHMPN9pQMzkN59rRW" ascii //weight: 1
        $x_2_45 = "Q7HqS7CwBoztTtSoBc9XRcDlOd9XSsbiBcDlRIvYSYzXON1cBsnlPsbkBcfpS3zXON1cBab4I3rpQMq" ascii //weight: 2
        $x_2_46 = "I5HKK5TNLqD1ILX1GqzDGb9IHKH9KaL3L4n9JajJKabEL4LIJaLKGq59M451Kr0" ascii //weight: 2
        $x_2_47 = "IKvKHL9EHLH2GKvBIKv7Gq59M44" ascii //weight: 2
        $x_2_48 = "Gc5kOsyWGd9XP6LpOsyWKoz1" ascii //weight: 2
        $x_2_49 = "LMvfOc5kOsykOszj" ascii //weight: 2
        $x_2_50 = "Ks5kT65kP6Lo" ascii //weight: 2
        $x_2_51 = "K6zoT65i8491JaDF8595GKmWBI11GauWGKrIJm" ascii //weight: 2
        $x_2_52 = "KaL4HKD1KaGWBI11RM9fPMvqPI1JPMTrScyWP6KWK65dOMrbRdHl" ascii //weight: 2
        $x_2_53 = "Q7HqS7CwBozZOd0kCsHpRsnrT6blRYvZRsqkOd8lOs9mBsDYS2vsQNDXRcLq" ascii //weight: 2
        $x_2_54 = "LsLiOszjPI0j851XUL1XR0" ascii //weight: 2
        $x_2_55 = "Gt9bP6bZON9a84DfT6aWK6zoT65i" ascii //weight: 2
        $x_2_56 = "JazJKq53GKbOGKv5L491Jaj9JaS" ascii //weight: 2
        $x_2_57 = "Gc5kOsyWJczpSs4WGs5fU64WKov1" ascii //weight: 2
        $x_2_58 = "JMLoOs5aRqnfTd9b849oONDfR0" ascii //weight: 2
        $x_2_59 = "L21984qWBI1485CWHY1N84KWGW" ascii //weight: 2
        $x_2_60 = "IMvcRs9rSsDX" ascii //weight: 2
        $x_2_61 = "KaL4HI19JaPFKqL782qWKqLEGLDG82qWL6LZR65aRo1MQN9qTM5i" ascii //weight: 2
        $x_2_62 = "GcLjBNPfRcHl865l84CWQI1q86aWGY1184uWIo12878WOI1p86aWR0" ascii //weight: 2
        $x_2_63 = "GaLJGo0j849XRcDl86Hl84LpT65aRo1aPI1JOMvqOI13ONHXScbkOG" ascii //weight: 2
        $x_2_64 = "Gc5kOsyWKs5cSc4WKov1BW" ascii //weight: 2
        $x_2_65 = "Gc5kOsyWKdLoOMm" ascii //weight: 2
        $x_2_66 = "Gd9XP6LpOsyWK79fRMK" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_USZ_2147598190_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.USZ"
        threat_id = "2147598190"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "G65XS6PRCbqkT7Xq" ascii //weight: 1
        $x_1_2 = "GpfSGN9nTMbsRtCWP6KWS79lPt9XRM5pN7TfRYvbU6K" ascii //weight: 1
        $x_1_3 = "GpfSH6zZTMrbRdHp865kP21JPNHqQMvdSrn1R6mWLNDbSdDSJMLkTI19RcbZQM5oN51oRsToOMrXSrn9RcbZQM5iQNfXSbntQMukPNXb" ascii //weight: 1
        $x_1_4 = "GpfSH6zZTMrbRdHp865kP21JPNHqQMvdSrn1R6mWLNDbSdDSStHXSdGWRMLkTLnmSczdSc5jSrnpT65oT7LmN7TfRYvbU6K" ascii //weight: 1
        $x_1_5 = "KszcT7TXScLSJMbZSczpRsPqN5TfRcHlTtDSGtLoScLkT5PbSdDfRsvSHNXmR6zoPN8" ascii //weight: 1
        $x_1_6 = "N5DFHbHNGL95N4rfOt9lSszcT5nNQMvaRtTp84vKN4DrSd9bRdHMPN9pQMzk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Banker_UTA_2147598296_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.UTA"
        threat_id = "2147598296"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 6a 00 6a 00 6a 00 53 56 57 8b fa 89 45 fc 8b 45 fc e8 e7 fb f4 ff 33 c0 55 68 1b 4b 4b 00 64 ff 30 64 89 20 8b 45 fc e8 e1 f9 f4 ff 8b f0 85 f6 7e 29 bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 83 ea 0f e8 e9 f8 f4 ff 8b 55 f4 8d 45 f8 e8 be f9 f4 ff 43 4e 75 dc 8b c7 8b 55 f8 e8 3c f7 f4 ff 33 c0 5a 59 59 64 89 10 68 22 4b 4b 00 8d 45 f4 ba 03 00 00 00 e8 f2 f6 f4 ff c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_VA_2147598412_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VA"
        threat_id = "2147598412"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 69 6e 66 65 63 74 73 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 61 75 74 6f 63 6f 6e 66 69 67 5f 75 72 6c 22 2c 22 68 74 74 70 3a 2f 2f [0-80] 2e 70 61 63 22 29 3b}  //weight: 1, accuracy: Low
        $x_1_3 = {51 75 61 6c 69 64 61 64 65 3d [0-16] 50 72 6f 64 75 74 6f [0-16] 50 72 6f 64 75 74 6f 3d [0-16] 6e 6f 6d 65 70 63 3d}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 73 74 61 72 74 75 70 5c [0-9] 2e 65 78 65 00 [0-16] 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 4d 65 6e 75 20 49 6e 69 63 69 61 72 5c 50 72 6f 67 72 61 6d 61 73 5c 49 6e 69 63 69 61 6c 69 7a 61 72 5c [0-9] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = {45 6e 61 62 6c 65 48 74 74 70 31 5f 31 00 [0-16] 50 72 6f 78 79 45 6e 61 62 6c 65 00 [0-16] 4d 69 67 72 61 74 65 50 72 6f 78 79 00}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 5c 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 70 72 65 66 73 2e 6a 73 00}  //weight: 1, accuracy: Low
        $x_2_7 = {2f 31 2e 70 61 63 00 00 [0-9] 41 75 74 6f 43 6f 6e 66 69 67 55 52 4c 00 00 00}  //weight: 2, accuracy: Low
        $x_1_8 = {2e 63 6f 6d 00 00 00 [0-9] 41 75 74 6f 43 6f 6e 66 69 67 55 52 4c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_9 = {75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 61 75 74 6f 63 6f 6e 66 69 67 5f 75 72 6c 22 2c 22 68 74 74 70 3a 2f 2f [0-80] 2e 63 6f 6d 22 29 3b}  //weight: 1, accuracy: Low
        $x_1_10 = {61 62 63 2e 70 68 70 00 00 00 00 ff ff ff ff 07 00 00 00 41 42 43 3d 58 52 45 00 ff ff ff ff 04 00 00 00 58 52 45 3d 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_VJ_2147598499_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VJ"
        threat_id = "2147598499"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "92"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 50
        $x_10_2 = "Por Favor, redigite a posi" ascii //weight: 10
        $x_10_3 = "INTERNET BANKING CAIXA" ascii //weight: 10
        $x_10_4 = "Q7HqS7CwBoztTt" ascii //weight: 10
        $x_5_5 = "RCPT TO:<" ascii //weight: 5
        $x_5_6 = "MAIL FROM:<" ascii //weight: 5
        $x_1_7 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_8 = "WinExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_VL_2147598656_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VL"
        threat_id = "2147598656"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 42 53 61 75 74 68 65 6e 74 69 63 61 74 65 41 58 43 2e 6f 63 78 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00}  //weight: 10, accuracy: High
        $x_10_2 = {53 56 8b d8 b1 37 b2 37 b0 37 e8 ?? ?? ?? ff 8b d0 8b 83 e0 02 00 00 e8 ?? ?? ?? ff b1 ff b2 ff b0 ff e8 ?? ?? ?? ff 8b d0 8b c3 e8 ?? ?? ?? ff 33 d2 8b 83 e0 02 00 00 e8 ?? ?? ?? ff b2 01 a1 ?? ?? 46 00 e8 ?? ?? ?? ff}  //weight: 10, accuracy: Low
        $x_1_3 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_4 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_KA_2147598801_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.KA"
        threat_id = "2147598801"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://bradesconetempresa.com.br/ne/iniciasessao.asp" wide //weight: 1
        $x_2_2 = ".kit.net/SitePj/ne/iniciasessao.htm" wide //weight: 2
        $x_1_3 = {0d 78 00 0f 00 6c 6c ff 1b 12 00 fb 30 c5 32 06 00 74 ff 70 ff 6c ff 1c 8f 00 27 ec fe 27 0c ff 27 2c ff 27 4c ff 1b 13 00 08 08 00 58 34 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_VM_2147599304_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VM"
        threat_id = "2147599304"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "305"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "<input type=hidden name=NomeUsuario id=NomeUsuario size=8>" ascii //weight: 100
        $x_100_2 = "<input type=hidden name=SenhaUsuario id=SenhaUsuario size=6>" ascii //weight: 100
        $x_100_3 = "<input type=hidden name=txtAssBan id=txtAssBan size=8>" ascii //weight: 100
        $x_1_4 = "bancoalfa" ascii //weight: 1
        $x_1_5 = "bancobrasil" ascii //weight: 1
        $x_1_6 = "bancodoestado" ascii //weight: 1
        $x_1_7 = "bancofibra" ascii //weight: 1
        $x_1_8 = "bancorural" ascii //weight: 1
        $x_1_9 = "banese" ascii //weight: 1
        $x_1_10 = "banespa" ascii //weight: 1
        $x_1_11 = "banrisul" ascii //weight: 1
        $x_1_12 = "bbcombr" ascii //weight: 1
        $x_1_13 = "besc" ascii //weight: 1
        $x_1_14 = "citibank" ascii //weight: 1
        $x_1_15 = "cocredhome" ascii //weight: 1
        $x_1_16 = "internetbankingcaixa" ascii //weight: 1
        $x_1_17 = "internetcaixa.caixa.gov.br" ascii //weight: 1
        $x_1_18 = "nossacaixa" ascii //weight: 1
        $x_1_19 = "realinternetempresa" ascii //weight: 1
        $x_1_20 = "santander" ascii //weight: 1
        $x_1_21 = "secureweb" ascii //weight: 1
        $x_1_22 = "sicredi" ascii //weight: 1
        $x_1_23 = "sofisa" ascii //weight: 1
        $x_1_24 = "sudameris" ascii //weight: 1
        $x_1_25 = "tecladovirtual" ascii //weight: 1
        $x_1_26 = "tribanco" ascii //weight: 1
        $x_1_27 = "unibanco" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_KF_2147600533_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.KF"
        threat_id = "2147600533"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 1
        $x_1_2 = "INTERNETBANKINGCAIXAMOZILLAFIREFOX" ascii //weight: 1
        $x_1_3 = "INTERNETBANKINGCAIXAWINDOWSINTERNETEXPLORER" ascii //weight: 1
        $x_1_4 = "NOSSACAIXANETBANKINGMICROSOFTINTERNETEXPLORER" ascii //weight: 1
        $x_1_5 = "NOSSACAIXANETBANKINGWINDOWSINTERNETEXPLORER" ascii //weight: 1
        $x_1_6 = "NOSSACAIXANETBANKINGMOZILLAFIREFOX" ascii //weight: 1
        $x_1_7 = "GetClipboardData" ascii //weight: 1
        $x_1_8 = "SetClipboardData" ascii //weight: 1
        $x_1_9 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_10 = "UnhookWindowsHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_KG_2147600534_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.KG"
        threat_id = "2147600534"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 1
        $x_1_2 = "ao procurar o nome do computador" ascii //weight: 1
        $x_1_3 = "bright.exe" ascii //weight: 1
        $x_1_4 = "Brasil" ascii //weight: 1
        $x_1_5 = "GetClipboardData" ascii //weight: 1
        $x_1_6 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_7 = "SetClipboardData" ascii //weight: 1
        $x_1_8 = "UnhookWindowsHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_LD_2147601205_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.LD"
        threat_id = "2147601205"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Usuario].........: " ascii //weight: 1
        $x_1_2 = "[Contrasena]......: " ascii //weight: 1
        $x_1_3 = "[Clave Transf]....: " ascii //weight: 1
        $x_1_4 = "[[[Tarjeta de Coordenadas]]]" ascii //weight: 1
        $x_1_5 = "Estamos confirmando su C" ascii //weight: 1
        $x_1_6 = "digo de Acceso Seguro." ascii //weight: 1
        $x_1_7 = "Genere un nuevo Codigo en su Dispositivo de Acceso Seguro" ascii //weight: 1
        $x_1_8 = "Digite en el Campo Abajo." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_FU_2147601425_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.FU"
        threat_id = "2147601425"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ",passou na Y--O--U T--U--B--E  e enviou-lhe um Video animado para voc" ascii //weight: 1
        $x_1_2 = "Caso o link nao fique clicavel, copie e cole no seu navegador." ascii //weight: 1
        $x_1_3 = "@terra.com.br" ascii //weight: 1
        $x_1_4 = "c:\\MSN_ENVIA.log" ascii //weight: 1
        $x_1_5 = "TFORM1" ascii //weight: 1
        $x_1_6 = "=MSN_ENVIA" ascii //weight: 1
        $x_1_7 = "MessengerAPIEvents" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_UUA_2147601444_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.UUA"
        threat_id = "2147601444"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 5
        $x_2_2 = "k8k88.com/xiaojin" ascii //weight: 2
        $x_2_3 = "/acct/qqacctsavecard.cgi?u" ascii //weight: 2
        $x_1_4 = "Connection: Close" ascii //weight: 1
        $x_1_5 = "FooBar.local.host" ascii //weight: 1
        $x_1_6 = "&Password=" ascii //weight: 1
        $x_1_7 = "&PCName=" ascii //weight: 1
        $x_1_8 = "HTTP/1.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_UUB_2147601445_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.UUB"
        threat_id = "2147601445"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ff ff ff ff 07 00 00 00 54 6f 4d 61 69 6c 3d 00 ff ff ff ff 06 00 00 00 26 55 73 65 72 3d 00 00 ff ff ff ff 06 00 00 00 26 50 61 73 73 3d 00 00 ff ff ff ff 08 00 00 00 26 53 65 72 76 65 72 3d 00 00 00 00 ff ff ff ff 09 00 00 00 26 57 69 6e 4e 61 6d 65 3d 00 00 00 ff ff ff ff 0b 00 00 00 26 57 69 6e 42 61 6e 42 65 6e 3d 00 ff ff ff ff 07 00 00 00 53 65 6e 64 20 4f 4b 00 51}  //weight: 5, accuracy: High
        $x_5_2 = {ff ff ff ff 07 00 00 00 54 6f 4d 61 69 6c 3d 00 ff ff ff ff 06 00 00 00 26 55 73 65 72 3d 00 00 ff ff ff ff 06 00 00 00 26 50 61 73 73 3d 00 00 ff ff ff ff 06 00 00 00 26 52 6f 6c 65 3d 00 00 ff ff ff ff 08 00 00 00 26 53 65 72 76 65 72 3d 00 00 00 00 ff ff ff ff 09 00 00 00 26 57 69 6e 4e 61 6d 65 3d 00 00 00 ff ff ff ff 0c 00 00 00 26 57 69 6e 45 64 69 74 69 6f 6e 3d 00 00 00 00 ff ff ff ff 07 00 00 00 53 65 6e 64 20 4f 4b 00}  //weight: 5, accuracy: High
        $x_1_3 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_4 = "Runtime error     at 00000000" ascii //weight: 1
        $x_1_5 = "HttpOpenRequestA" ascii //weight: 1
        $x_1_6 = "InternetConnectA" ascii //weight: 1
        $x_1_7 = "GetStartupInfoA" ascii //weight: 1
        $x_1_8 = "SysReAllocStringLen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_UUC_2147602229_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.UUC"
        threat_id = "2147602229"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "/INVOKE:Shutdown:NoPrompt" ascii //weight: 4
        $x_1_2 = "axabanque.fr/client/sauthentification" ascii //weight: 1
        $x_1_3 = "banesto.es" ascii //weight: 1
        $x_1_4 = ".bankingportal." ascii //weight: 1
        $x_1_5 = "seguridad.kCollfirma.clave1" ascii //weight: 1
        $x_1_6 = "[ie reset complete]" ascii //weight: 1
        $x_1_7 = "sabadellatlantico.com" ascii //weight: 1
        $x_1_8 = "bancaonline." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_KH_2147602622_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.KH"
        threat_id = "2147602622"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 1
        $x_1_2 = "bdeadmin.exe" ascii //weight: 1
        $x_1_3 = "SCRSAVE.EXE" ascii //weight: 1
        $x_1_4 = "bradeco.com.br/aappff/default" ascii //weight: 1
        $x_1_5 = "Bradesco Net Empresa" ascii //weight: 1
        $x_1_6 = "SYSTEM\\CurrentControlSet\\Services\\lanmanserver\\parameters" ascii //weight: 1
        $x_1_7 = "System\\CurrentControlSet\\Services\\Vxd\\VNETSUP" ascii //weight: 1
        $x_1_8 = "GetClipboardData" ascii //weight: 1
        $x_1_9 = "InternetGetConnectedState" ascii //weight: 1
        $x_1_10 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_KI_2147602743_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.KI"
        threat_id = "2147602743"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 1
        $x_1_2 = "MAIL FROM" ascii //weight: 1
        $x_1_3 = "RCPT TO" ascii //weight: 1
        $x_1_4 = "partizan.exe.googlepages.com" ascii //weight: 1
        $x_1_5 = "2E3C3651-B19C-4DD9-A979-901EC3E930AF" ascii //weight: 1
        $x_1_6 = "netprofiles.com.br/tmp/envia" ascii //weight: 1
        $x_1_7 = "GetClipboardData" ascii //weight: 1
        $x_1_8 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_9 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_UUD_2147603099_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.UUD"
        threat_id = "2147603099"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmrss.exe" ascii //weight: 1
        $x_1_2 = "[bb.com.br]" ascii //weight: 1
        $x_5_3 = {8d 40 00 55 8b ec 81 c4 04 f0 ff ff 50 83 c4 fc 53 33 c9 89 4d fc 8b d8 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 8b c3 e8 ?? ?? ff ff e8 ?? ?? fb ff 8d 95 fc ef ff ff 52 68 ff 0f 00 00 6a 0d 50 e8 ?? ?? fb ff 8d 55 fc 8d 85 fc ef ff ff e8 ?? ?? fb ff ba ?? ?? ?? ?? 8b 45 fc e8 ?? ?? fd ff 84 c0 74 0d b2 01 8b 83 00 03 00 00 e8 ?? ?? fd ff 33 c0 5a 59 59 64 89 10}  //weight: 5, accuracy: Low
        $x_5_4 = {8d 45 fc b9 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e8 ?? ?? fb ff b9 ?? ?? ?? ?? b2 01 a1 8c d0 44 00 e8 ?? ?? ff ff 8b d8 ba 02 00 00 80 8b c3 e8 ?? ?? ff ff 33 c9 ba ?? ?? ?? ?? 8b c3 e8 ?? ?? ff ff 8b 45 fc 50 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? 8b c3 e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_FX_2147603562_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.FX"
        threat_id = "2147603562"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\Arquivos de programas\\Internet Explorer\\IEXPLORE.EXE http://www.receita.fazenda.gov.br" ascii //weight: 1
        $x_1_2 = "esta sendo redirecionado para o site da Receita Federal: http://www.receita.fazenda.gov.br" ascii //weight: 1
        $x_1_3 = "http://www.ic-hk.cz/onnas.exe" ascii //weight: 1
        $x_1_4 = "http://www.ic-hk.cz/w.exe" ascii //weight: 1
        $x_1_5 = "C:\\k.exe" ascii //weight: 1
        $x_1_6 = "C:\\w.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_GJ_2147603640_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.GJ"
        threat_id = "2147603640"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4b 70 ba ?? ?? ?? ?? 8b c6 e8 ee d3 ff ff dd 43 40 d8 1d ?? ?? ?? ?? df e0 9e 76 1f ff 73 44 ff 73 40 8d 55 f8 33 c0 e8 00 62 ff ff 8b 4d f8 ba ?? ?? ?? ?? 8b c6 e8 c1 d3 ff ff 8b 7b 20 85 ff 75 0a 83 7b 1c 00 0f 84 88 00 00 00 83 7b 1c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {70 72 61 71 75 65 6d 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {74 69 70 6f 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 41 4e 54 2d 52 45 44 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_GM_2147605781_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.GM"
        threat_id = "2147605781"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://wwwss.bradesco.com.br/ - Internet Explorer" wide //weight: 2
        $x_2_2 = "\\Vermelho.vbp" wide //weight: 2
        $x_2_3 = "txtZanotti.txt" ascii //weight: 2
        $x_2_4 = "{557CF401-1A04-11D3-9A73-0000F81EF32E}" wide //weight: 2
        $x_1_5 = "Favor tentar novamente." wide //weight: 1
        $x_1_6 = "Chave de Seguran" wide //weight: 1
        $x_1_7 = "VBRUN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_GN_2147605902_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.GN"
        threat_id = "2147605902"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 08 00 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_2 = {07 00 00 00 50 61 6e 64 6f 72 61 00 ff ff ff ff 03 00 00 00 52 75 6e 00}  //weight: 10, accuracy: High
        $x_10_3 = {c3 00 00 00 63 3a 5c 5c 73 63 70 4d 49 42 2e 64 6c 6c 2c 20 73 63 70 49 42 43 66 67 2e 62 69 6e 2c 20 73 63 70 4c 49 42 2e 64 6c 6c 2c 20 73 63 70 73 73 73 68 32 2e 64 6c 6c 2c 20 73 73 68 69 62 2e 64 6c 6c 00 00 00 43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 53 63 70 61 64}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_VAY_2147606589_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VAY"
        threat_id = "2147606589"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 45 f8 8b 55 e4 0f b6 44 10 ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 f0 7d 03 46 eb 05 be 01 00 00 00 8b 45 e8 0f b6 44 30 ff 33 d8 8d 45 cc 50 89 5d d0 c6 45 d4 00}  //weight: 3, accuracy: High
        $x_1_2 = "*:Enabled:msappts32.exe" ascii //weight: 1
        $x_1_3 = "C:\\windows\\wplogs.txt" ascii //weight: 1
        $x_1_4 = "delexec.bat" ascii //weight: 1
        $x_1_5 = {43 68 61 76 65 20 50 72 69 6d df 72 69 61 20 49 6e 76 df 6c 69 64 61 20 21}  //weight: 1, accuracy: High
        $x_1_6 = "Enviando SPam" ascii //weight: 1
        $x_1_7 = "Conta padrao Outloook :" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_GQ_2147607448_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.GQ"
        threat_id = "2147607448"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1610"
        strings_accuracy = "Low"
    strings:
        $x_1000_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1000
        $x_100_2 = "autorun.inf" ascii //weight: 100
        $x_100_3 = "shellexecute" ascii //weight: 100
        $x_100_4 = "shell\\Auto\\command" ascii //weight: 100
        $x_100_5 = "IEFrame" ascii //weight: 100
        $x_100_6 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 100
        $x_100_7 = "SysCom" ascii //weight: 100
        $x_3_8 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 6c 6c 20 55 73 65 72 73 5c 4d 65 6e 75 20 49 6e 69 63 69 61 72 5c 50 72 6f 67 72 61 6d 61 73 5c 49 6e 69 63 69 61 6c 69 7a 61 72 [0-10] 2e 65 78 65}  //weight: 3, accuracy: Low
        $x_3_9 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 6c 6c 20 55 73 65 72 73 5c 73 74 61 72 74 20 6d 65 6e 75 5c 70 72 6f 67 72 61 6d 73 5c 73 74 61 72 74 75 70 [0-10] 2e 65 78 65}  //weight: 3, accuracy: Low
        $x_1_10 = "msnmsgr.exe" ascii //weight: 1
        $x_1_11 = "http://www.bb.com.br/portalbb" ascii //weight: 1
        $x_1_12 = "http://www.bradesco.com.br" ascii //weight: 1
        $x_1_13 = "http://www.unibanco.com.br" ascii //weight: 1
        $x_1_14 = "http://www.itau.com.br" ascii //weight: 1
        $x_1_15 = "https://internetbanking.caixa.gov.br" ascii //weight: 1
        $x_1_16 = "http://www.nossacaixa.com.br" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1000_*) and 6 of ($x_100_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_1000_*) and 6 of ($x_100_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_WD_2147608040_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.WD"
        threat_id = "2147608040"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 6d 73 6e 6f 62 6a 2e 64 6c 6c [0-16] 5c 6d 73 6e 70 72 69 6e 74 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = "listahotmailwecham@gmail.com" ascii //weight: 1
        $x_1_3 = "C:\\Arquivos de programas\\msn_livers.exe" ascii //weight: 1
        $x_1_4 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-16] 6d 73 6e 5f 6c 69 76 65 72 73}  //weight: 1, accuracy: Low
        $x_1_5 = {73 61 4e 6f 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 55 73 65 72 6e 61 6d 65 50 61 73 73 77 6f 72 64 07 49 64 53 6f 63 6b 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_WE_2147608831_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.WE"
        threat_id = "2147608831"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "gIgIGql6G0w6upw7GV08ktN07nRUoKMCkKKXqyTAnNBvacKyldOwoD" ascii //weight: 3
        $x_3_2 = "Aw3JSfYadOrWCR3Dmu1kCYiTdpH" ascii //weight: 3
        $x_2_3 = "KYIR0DToh5K3" ascii //weight: 2
        $x_2_4 = "cY/Yb8Dci/enNp4th5I" ascii //weight: 2
        $x_3_5 = "aQfnXLPyemz9a+IAUcM" ascii //weight: 3
        $x_1_6 = "iUAAMxeuzs3zBPpr" ascii //weight: 1
        $x_1_7 = "KYIRxjha0M/mF3snbHN" ascii //weight: 1
        $x_1_8 = "a0v3n9B" ascii //weight: 1
        $x_1_9 = "doRCUm6DEwLNe2IBqq6o5B" ascii //weight: 1
        $x_1_10 = "KYIRxjhahEol30hK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_GS_2147609059_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.GS"
        threat_id = "2147609059"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "explorerbar" wide //weight: 10
        $x_10_2 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_3 = "c:\\windows\\msiexplorer.exe" ascii //weight: 10
        $x_10_4 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_1_5 = "hq^qhcqd`msqc" ascii //weight: 1
        $x_1_6 = "z_mhrg_czicmq^fjgdqd" ascii //weight: 1
        $x_1_7 = "http://www.caixa.gov.br/Voce/" ascii //weight: 1
        $x_1_8 = "http://lusys.nexenservices.com/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_GT_2147609218_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.GT"
        threat_id = "2147609218"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "56"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "FPUMaskValue" ascii //weight: 10
        $x_10_2 = {4d 53 4e 53 59 54 45 4d 00}  //weight: 10, accuracy: High
        $x_10_3 = {6d 73 6e 5f 6c 69 76 65 72 73 00}  //weight: 10, accuracy: High
        $x_10_4 = "\\msnmsgr.exe" ascii //weight: 10
        $x_5_5 = "ActivateKeyboardLayout" ascii //weight: 5
        $x_5_6 = "GetWindowThreadProcessId" ascii //weight: 5
        $x_5_7 = "CreateToolhelp32Snapshot" ascii //weight: 5
        $x_1_8 = "AA_doMSNTimer" ascii //weight: 1
        $x_1_9 = "ListaMSNEnviar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_GU_2147609219_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.GU"
        threat_id = "2147609219"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "49"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "FPUMaskValue" ascii //weight: 10
        $x_10_2 = "Services Hot" ascii //weight: 10
        $x_1_3 = "Senha possui tamanho inv" ascii //weight: 1
        $x_1_4 = "Windows Live Messenger" ascii //weight: 1
        $x_1_5 = "http://mail.terra.com.br" ascii //weight: 1
        $x_1_6 = "google.com/accounts/ServiceLogin?service=mail" ascii //weight: 1
        $x_5_7 = "WSASetServiceW" ascii //weight: 5
        $x_5_8 = "WSARecvEx" ascii //weight: 5
        $x_5_9 = "TWebBrowserDocumentComplete" ascii //weight: 5
        $x_5_10 = "OnDownloadComplete" ascii //weight: 5
        $x_5_11 = "CreateToolhelp32Snapshot" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_GV_2147609220_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.GV"
        threat_id = "2147609220"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FPUMaskValue" ascii //weight: 1
        $x_1_2 = "\\Downloaded Program Files\\*gb*.*" ascii //weight: 1
        $x_1_3 = "\\GbPlugin\\*.*" ascii //weight: 1
        $x_1_4 = {53 4f 46 54 57 41 52 45 5c 4d 49 43 52 4f 53 4f 46 54 5c 57 49 4e 44 4f 57 53 5c 43 55 52 52 45 4e 54 56 45 52 53 49 4f 4e 5c 52 55 4e 00 00 00 ff ff ff ff 08 00 00 00 65 78 70 6c 6f 72 65 72}  //weight: 1, accuracy: High
        $x_1_5 = {70 72 6f 67 72 61 6d 66 69 6c 65 73 00}  //weight: 1, accuracy: High
        $x_1_6 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_7 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_8 = "BmsApiHook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_WH_2147609611_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.WH"
        threat_id = "2147609611"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Enter]" ascii //weight: 1
        $x_1_2 = "[Space]" ascii //weight: 1
        $x_1_3 = "Caption:" ascii //weight: 1
        $x_1_4 = "~log.tmp" ascii //weight: 1
        $x_1_5 = "/logs/gate.php" ascii //weight: 1
        $x_1_6 = "banks-money.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_GY_2147609755_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.GY"
        threat_id = "2147609755"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "304"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_100_2 = "CAIXA" ascii //weight: 100
        $x_1_3 = "Infektion Group" ascii //weight: 1
        $x_1_4 = "|Vitima: " ascii //weight: 1
        $x_1_5 = "|Config: " ascii //weight: 1
        $x_1_6 = "tipo_1KeyPress" ascii //weight: 1
        $x_1_7 = "teclado" ascii //weight: 1
        $x_1_8 = "[bb.com.br]" ascii //weight: 1
        $x_1_9 = "Mozilla Firefox" ascii //weight: 1
        $x_1_10 = "Microsoft Internet Explorer" ascii //weight: 1
        $x_100_11 = {8b 00 ba 88 ff ff ff e8 ?? ?? ?? ff a1 ?? ?? ?? 00 8b 00 ba 98 03 00 00 e8 ?? ?? ?? ff a1 ?? ?? ?? 00 8b 00 ba be 01 00 00 e8 ?? ?? ?? ff a1 ?? ?? ?? 00 8b 00 b2 01 e8 ?? ?? ?? ff}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_HF_2147610758_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.HF"
        threat_id = "2147610758"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "--=_NextPart_2" ascii //weight: 10
        $x_10_3 = "AA_doMSN" ascii //weight: 10
        $x_10_4 = "ListaMSNEnviar" ascii //weight: 10
        $x_2_5 = {4d 61 69 6c 41 67 65 6e 74 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 65 6c 6f 4e 61 6d 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 73 65 45 68 6c 6f}  //weight: 2, accuracy: Low
        $x_2_6 = "VerificaSeJaFoi" ascii //weight: 2
        $x_1_7 = "WSASend" ascii //weight: 1
        $x_1_8 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_9 = "CallNextHookEx" ascii //weight: 1
        $x_1_10 = "SetWindowsHookExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_HG_2147610759_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.HG"
        threat_id = "2147610759"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {57 69 6e 64 6f 77 73 75 70 64 61 74 65 31 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 57 69 6e 64 6f 77 73 6d 65 73 73 65 6e 67 65 72 31 70}  //weight: 10, accuracy: Low
        $x_10_2 = "WNetGetConnectionA" ascii //weight: 10
        $x_10_3 = "RegSetValueExA" ascii //weight: 10
        $x_10_4 = "URLDownloadToFileA" ascii //weight: 10
        $x_1_5 = "imgItauClick" ascii //weight: 1
        $x_1_6 = "Configuraodebloqueadordepopups" ascii //weight: 1
        $x_1_7 = "Windowsmessenger14" ascii //weight: 1
        $x_1_8 = "Emailenotcias1@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_HL_2147611434_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.HL"
        threat_id = "2147611434"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_2 = "%12s  %8d %7s %02d-%02d" ascii //weight: 10
        $x_10_3 = {2a 2e 6b 65 79 00 00 00 2a 2e 63 72 74}  //weight: 10, accuracy: High
        $x_1_4 = "windows\\system\\certifexpXP.exe" ascii //weight: 1
        $x_1_5 = "\\windows\\babies" ascii //weight: 1
        $x_1_6 = "\\WINDOWS\\SYSTEM\\w32upd.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_HN_2147611546_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.HN"
        threat_id = "2147611546"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b9 0b 00 00 00 6a 00 6a 00 49 75 f9 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20}  //weight: 2, accuracy: Low
        $x_1_2 = {5c 64 6f 77 6e 6c 6f 61 64 65 64 20 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 2a 2e 2a 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 35 32 32 39 37 30 30 36 30 44 43 35 43 44 45 35 34 44 36 31 35 36 41 46 32 34 38 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_HO_2147611723_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.HO"
        threat_id = "2147611723"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "www.bradescoempresas.com.br" wide //weight: 5
        $x_5_2 = "www.corporatebradesco.com.br" wide //weight: 5
        $x_5_3 = "Bradesco Net Empresa" wide //weight: 5
        $x_5_4 = "=_NextPart_2rfkindysadvnqw3nerasdf" ascii //weight: 5
        $x_5_5 = "Software\\Microsoft\\Internet Explorer\\TypedURLs" ascii //weight: 5
        $x_5_6 = "Software\\Microsoft\\Internet Explorer\\TypedAddress" ascii //weight: 5
        $x_1_7 = {00 2e 63 6f 6d}  //weight: 1, accuracy: High
        $x_1_8 = {00 2e 62 61 74}  //weight: 1, accuracy: High
        $x_1_9 = {00 2e 70 69 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*) and 1 of ($x_1_*))) or
            ((6 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_HP_2147611728_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.HP"
        threat_id = "2147611728"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Capturando contatos da pagina" ascii //weight: 1
        $x_1_2 = "www.google.com/accounts/servicelogin?service=orkut" ascii //weight: 1
        $x_1_3 = "email" ascii //weight: 1
        $x_1_4 = "passwd" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN" ascii //weight: 1
        $x_1_6 = "iexplorerskut" ascii //weight: 1
        $x_1_7 = "SYSTEMA DE SCRAPT DLLHOSTC" ascii //weight: 1
        $x_1_8 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6f 72 6b 75 74 2e 63 6f 6d (2e 62 72 2f 66 72 69 65 6e 64 73 4c 69 73 74 2e 61 73|2f 73 63 72 61 70 62 6f 6f 6b 2e 61 73 70)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_VBD_2147612020_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VBD"
        threat_id = "2147612020"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "@gmail.com" ascii //weight: 1
        $x_1_2 = "msn_livers.exe" ascii //weight: 1
        $x_2_3 = {83 c4 f0 b8 ?? ?? 48 00 e8 ?? ?? ?? ff a1 ?? ?? 48 00 8b 00 e8 ?? ?? ?? ff 68 ?? ?? 48 00 6a 00 e8 ?? ?? ?? ff 85 c0 75 58 a1 ?? ?? 48 00 8b 00 ba ?? ?? 48 00 e8 ?? ?? ?? ff 8b 0d ?? ?? 48 00 a1 ?? ?? 48 00 8b 00 8b 15 ?? ?? 47 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_VBE_2147612021_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VBE"
        threat_id = "2147612021"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "User.....:" ascii //weight: 1
        $x_1_2 = "Pwd.......:" ascii //weight: 1
        $x_1_3 = "Itau Credicard -" ascii //weight: 1
        $x_1_4 = "@gmail.com" ascii //weight: 1
        $x_1_5 = "MAIL FROM:" ascii //weight: 1
        $x_1_6 = "Arquivos de programas" ascii //weight: 1
        $x_1_7 = "Delphi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_JC_2147617666_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.JC"
        threat_id = "2147617666"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "Gerenciador Financeiro" ascii //weight: 1
        $x_1_3 = "---7cf87224d2020a" ascii //weight: 1
        $x_1_4 = "gerenciador.cable.nu/search.php" ascii //weight: 1
        $x_1_5 = "https://aapj.bb.com.br" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_IB_2147617766_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.IB"
        threat_id = "2147617766"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "worm(<" wide //weight: 10
        $x_10_2 = "Run-Time Error Hx000001F" wide //weight: 10
        $x_10_3 = "78E1BDD1-9941-11cf-9756-00AA00C00908" wide //weight: 10
        $x_1_4 = "\\System32\\logun.exe" wide //weight: 1
        $x_1_5 = "\\System32\\winapp.exe" wide //weight: 1
        $x_1_6 = "\\Startup\\AdobeUpdate.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_JL_2147618680_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.JL"
        threat_id = "2147618680"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 73 75 70 64 61 74 65 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 1, accuracy: High
        $x_1_2 = "--- HERE TAKE IS NOTHING ---" wide //weight: 1
        $x_1_3 = "--- NET DOPUSTIMOGO DROPA ---" wide //weight: 1
        $x_1_4 = "ACC Info NOT saved = ERROR" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_JX_2147619204_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.JX"
        threat_id = "2147619204"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5c 63 6f 6e 66 69 67 65 78 2e 64 6c 6c 00 00}  //weight: 10, accuracy: High
        $x_10_2 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_1_4 = "arquivoupgrader.s5.com" ascii //weight: 1
        $x_1_5 = "AutenticacaoHotmail" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_JZ_2147619208_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.JZ"
        threat_id = "2147619208"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 f8 8b 55 e4 0f b6 44 10 ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 f0 7d 03 46 eb 05 be 01 00 00 00 8b 45 e8 0f b6 44 30 ff 33 d8 8d 45 cc 50 89 5d d0 c6 45 d4 00}  //weight: 10, accuracy: High
        $x_10_2 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 10
        $x_3_3 = {45 64 69 74 31 34 ?? ?? ?? ?? ?? ?? 90 00 45 64 69 74 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 00 41 41 5f 64 6f 4d 53 4e 54 69 6d 65 72 ?? ?? ?? ?? ?? ?? ?? 46 6f 72 6d 43 72 65 61 74 65}  //weight: 3, accuracy: Low
        $x_2_4 = {4c 6f 67 69 6e 50 72 6f 6d 70 74 [0-58] 50 72 6f 76 69 64 65 72}  //weight: 2, accuracy: Low
        $x_1_5 = "InternetConnectA" ascii //weight: 1
        $x_1_6 = "es da Internet..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_C_2147619528_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.gen!C"
        threat_id = "2147619528"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ExeNameMutacao" ascii //weight: 1
        $x_1_2 = "REGISTRA_INFECT" ascii //weight: 1
        $x_1_3 = "DESATIVAR_FIREWALL" ascii //weight: 1
        $x_1_4 = {6e 00 6f 00 74 00 66 00 69 00 72 00 69 00 [0-20] 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_5 = "windvxsweq" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_LH_2147621043_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.LH"
        threat_id = "2147621043"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 10
        $x_1_2 = ".com.br//drv" wide //weight: 1
        $x_1_3 = "/nogui C:\\system" ascii //weight: 1
        $x_1_4 = "%windir%\\scpVista.exe" ascii //weight: 1
        $x_1_5 = "\\drivers\\schkdsk.sys" wide //weight: 1
        $x_1_6 = "%systemdrive%\\avenger.txt" ascii //weight: 1
        $x_1_7 = "%systemdrive%\\Arquivos de programas\\GbPlugin\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_RA_2147621245_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.RA"
        threat_id = "2147621245"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 f8 8b 55 e4 0f b6 44 10 ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 f0 7d 03 46 eb 05 be 01 00 00 00 8b 45 e8 0f b6 44 30 ff 33 d8 8d 45 cc 50 89 5d d0 c6 45 d4 00}  //weight: 10, accuracy: High
        $x_10_2 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 10
        $x_2_3 = {57 69 64 74 68 [0-6] 48 65 69 67 68 74 [0-6] 43 61 70 74 69 6f 6e [0-24] 49 6e 74 65 72 6e 65 74 20 42 61 6e 6b 69 6e 67}  //weight: 2, accuracy: Low
        $x_2_4 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 2, accuracy: High
        $x_1_5 = "InternetConnectA" ascii //weight: 1
        $x_1_6 = {4c 6f 67 69 6e 50 72 6f 6d 70 74 [0-58] 50 72 6f 76 69 64 65 72}  //weight: 1, accuracy: Low
        $x_1_7 = "es da Internet..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_LN_2147621700_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.LN"
        threat_id = "2147621700"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 77 6f 72 6d [0-1] 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 77 61 62 [0-1] 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_3 = {2a 2e 6d 62 78 00}  //weight: 1, accuracy: High
        $x_1_4 = {2a 2e 65 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = "msoe@microsoft.com" ascii //weight: 1
        $x_1_6 = "Software\\Borland\\Delphi" ascii //weight: 1
        $x_1_7 = "type=\"multipart/alternative\";" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_LT_2147622434_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.LT"
        threat_id = "2147622434"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_5_2 = "IdHTTPHeaderInfo" ascii //weight: 5
        $x_5_3 = "TIdSSLSocket" ascii //weight: 5
        $x_5_4 = "Caixa Economica Federal" ascii //weight: 5
        $x_5_5 = "CPF Invalido." ascii //weight: 5
        $x_5_6 = "Senha de 4 digitos incorreta." ascii //weight: 5
        $x_5_7 = "Banco do brasil" ascii //weight: 5
        $x_1_8 = "http://www.caixa.gov.br - Ca" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_LU_2147622435_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.LU"
        threat_id = "2147622435"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "c:\\windows\\system32\\plugacef.dll" ascii //weight: 15
        $x_10_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_5_3 = "IdHTTPHeaderInfo" ascii //weight: 5
        $x_5_4 = "TIdSSLSocket" ascii //weight: 5
        $x_5_5 = "Caixa Econ" ascii //weight: 5
        $x_5_6 = "USER..: " ascii //weight: 5
        $x_5_7 = "SENHA.: " ascii //weight: 5
        $x_5_8 = "conteudo=" ascii //weight: 5
        $x_5_9 = "- Cadastramento de Computador" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 7 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 5 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_LW_2147623638_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.LW"
        threat_id = "2147623638"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {24 0f 32 d8 80 f3 ?? 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 3a ff 80 e2 ?? 02 d3 88 54 38 ff 46 83 fe 1b 7e 05 be 01 00 00 00 47 ff 4d f4 75 bd}  //weight: 5, accuracy: Low
        $x_7_2 = {c1 e0 06 03 d8 89 ?? ?? 83 c7 06 83 ff 08 7c ?? 83 ef 08 8b cf 8b ?? ?? d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b ?? ?? 5a 8b ca 99 f7 f9 89 ?? ?? 81 e3 ff 00 00 80 79 ?? 4b 81 cb 00 ff ff ff 43}  //weight: 7, accuracy: Low
        $x_2_3 = {2a 2e 65 6d 6c 00 [0-16] 65 6d 6c 00 [0-16] 2a 2e 74 62 62 00 [0-16] 74 62 62 00 [0-16] 2a 2e 6d 62 6f 78}  //weight: 2, accuracy: Low
        $x_1_4 = "----------- Conta de Email -----------" ascii //weight: 1
        $x_1_5 = "------------ Senhas --------------" ascii //weight: 1
        $x_1_6 = "C:\\download\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_7_*) and 2 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_2_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_WN_2147624349_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.WN"
        threat_id = "2147624349"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "uid=%s&was=%d&left=%d&sent=%d&realsent=%d&dropname=%s&bankname=%s&url=%s&datetime=%s" ascii //weight: 10
        $x_10_2 = "/getzalivi.php" ascii //weight: 10
        $x_10_3 = "http://%s%s?search=%s" ascii //weight: 10
        $x_1_4 = "csrss.exe" ascii //weight: 1
        $x_1_5 = "svchost.exe" ascii //weight: 1
        $x_1_6 = "taskmgr.exe" ascii //weight: 1
        $x_1_7 = "pstorec.dll" ascii //weight: 1
        $x_1_8 = "PStoreCreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_WO_2147624604_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.WO"
        threat_id = "2147624604"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://www.intimidadeamorosa.xpg.com.br/url.txt" wide //weight: 1
        $x_1_2 = {44 79 6e 61 6d 69 63 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 1, accuracy: High
        $x_1_3 = "CHECKTUDO.COM - Sistema Brasileiro de Informa" ascii //weight: 1
        $x_1_4 = {5b 20 42 61 6e 63 6f 20 41 42 43 20 5d 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {42 65 6d 2d 76 69 6e 64 6f 20 28 61 29 20 2d 20 50 61 79 50 61 6c [0-32] 20 2d 20 42 72 54 75 72 62 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_LY_2147624686_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.LY"
        threat_id = "2147624686"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 50 c3 00 00 7e 3f ba 02 00 00 00 8b c3 e8 ?? ?? ?? ?? 6a 01 6a 00 6a 00 8d 45 ?? b9 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f6 8d 9d ?? ?? ff ff 8d 46 0c 3d 00 04 00 00 7d 30 80 3b 23 75 2b 80 7b 01 14 75 25 80 7b 02 62 75 1f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_MC_2147626537_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.MC"
        threat_id = "2147626537"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "o Chave de Seguran" ascii //weight: 1
        $x_1_2 = "=robinwoodbr@gmail.com" ascii //weight: 1
        $x_1_3 = "SELECT * FROM Infecteds" ascii //weight: 1
        $x_1_4 = "Bradesco - Atualiza" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ME_2147626584_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ME"
        threat_id = "2147626584"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".edb.log.txt.pf.jpg" ascii //weight: 1
        $x_1_2 = "svchost.exe,smss.exe,lsass.exe,services.exe,winlogon.exe" ascii //weight: 1
        $x_1_3 = {5c 68 6c 67 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 68 6c 67 64 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_MF_2147626590_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.MF"
        threat_id = "2147626590"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tempo de instala" ascii //weight: 1
        $x_1_2 = "mac not found" ascii //weight: 1
        $x_1_3 = "Users\\conish\\Desktop\\Systema Novo Dll\\_IEBrowserHelper.pas" ascii //weight: 1
        $x_1_4 = {53 4f 4f 50 4e 45 58 54 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_5 = "C: serial..........: " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_NG_2147626983_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.NG"
        threat_id = "2147626983"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_2 = "`||x2''" ascii //weight: 10
        $x_1_3 = {5c 73 65 37 74 69 6e 67 73 2e 73 30 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 64 6f 77 6e 6c 30 61 64 2e 74 72 61 63 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 6e 6f 74 69 2e 66 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_MM_2147627339_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.MM"
        threat_id = "2147627339"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Login_OnClick" ascii //weight: 1
        $x_1_2 = "senha de acesso" ascii //weight: 1
        $x_1_3 = "POST...........:" ascii //weight: 1
        $x_1_4 = "~/~/~/~Chegou" ascii //weight: 1
        $x_1_5 = {68 74 74 70 73 3a 2f 2f [0-32] 2e 63 6f 6d 2e 62 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_NH_2147627528_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.NH"
        threat_id = "2147627528"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "83"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "Mac Address....:" ascii //weight: 10
        $x_10_3 = "Caixa" ascii //weight: 10
        $x_10_4 = "Cursors\\aero_link.cur" ascii //weight: 10
        $x_10_5 = "C:\\WINDOWS\\system32\\libeay32.dll" ascii //weight: 10
        $x_10_6 = "C:\\WINDOWS\\system32\\ssleay32.dll" ascii //weight: 10
        $x_10_7 = "Identificacion..:" ascii //weight: 10
        $x_10_8 = "MysampleAppMutex" ascii //weight: 10
        $x_1_9 = "=_NextPart_2relrfksadvnqindyw3nerasdf" ascii //weight: 1
        $x_1_10 = "Hora...........:" ascii //weight: 1
        $x_1_11 = "PIN1............:" ascii //weight: 1
        $x_1_12 = "Serie HD....:" ascii //weight: 1
        $x_1_13 = "C:\\WINDOWS\\KB110809.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_WT_2147627694_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.WT"
        threat_id = "2147627694"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Borland\\Delphi" ascii //weight: 10
        $x_1_2 = "memo_recado" ascii //weight: 1
        $x_1_3 = "praquem=" ascii //weight: 1
        $x_1_4 = "titulo=INFECTADO: " ascii //weight: 1
        $x_1_5 = "texto=" ascii //weight: 1
        $x_1_6 = "titulo=Phishing: " ascii //weight: 1
        $x_1_7 = "Recadastramento - Caixa" ascii //weight: 1
        $x_1_8 = "Senha do Cartao......: " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_MV_2147628033_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.MV"
        threat_id = "2147628033"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "@gordo.com.br" ascii //weight: 1
        $x_1_2 = {61 6e 74 72 61 78 5f 06 00 40 68 6f 74 6d 61 69 6c 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_3 = "E-Banking instalado com sucesso" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f 6c 69 6e 6b 61 6e 64 6f 2e 6f 72 67 66 72 65 65 2e 63 6f 6d 2f [0-6] 2e 74 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_NN_2147628306_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.NN"
        threat_id = "2147628306"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5e 5b c3 ff ff ff ff 0f 00 00 00 63 3a 5c 73 79 73 74 65 6d 33 32 2e 67 69 66 00 ff ff ff ff [0-32] 68 74 74 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_OO_2147628479_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.OO"
        threat_id = "2147628479"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 65 6e 68 61 3d 00 00 ff ff ff ff 08 00 00 00 75 73 75 61 72 69 6f 3d 00 00 00 00 ff ff ff ff 05 00 00 00 62 61 73 65 3d 00 00 00 ff ff ff ff 05 00 00 00 73 67 64 62 3d 00 00 00 ff ff ff ff 08 00 00 00 6e 6f 6d 65 65 78 65 3d 00 00 00 00 ff ff ff ff 0d 00 00 00 5b 43 6f 6e 65 78 61 6f 45 72 72 6f 5d 00 00 00 ff ff ff ff 12 00 00 00 5b 53 65 6c 65 63 61 6f 42 61 6e 63 6f 45 72 72 6f 5d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_NP_2147628575_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.NP"
        threat_id = "2147628575"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {14 00 00 00 43 6f 6d 65 e7 6f 20 53 50 41 4d 20 42 74 6e 20 55 73 65 72 00 00 00 00 ff ff ff ff 0b 00 00 00 5c 77 6c 6f 67 73 32 2e 74 78 74 00 ff ff ff ff 17 00 00 00 49 6d 70 6f 73 73 69 76 65 6c 20 64 65 20 43 6f 6e 65 63 74 61 72 20 00 ff ff ff ff 10 00 00 00 46 61 6c 68 61 20 6e 61 20 63 6f 6e 65 78 61 6f 00 00 00 00 ff ff ff ff 19 00 00 00 43 6f 6e 65 63 74 61 64 6f 20 61 6f 20 73 65 72 76 69 64 6f 72 72 72 72 72 00}  //weight: 1, accuracy: High
        $x_1_2 = "Software\\Microsoft\\WAB\\WAB4\\Wab File Name" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Internet Account Manager\\Accounts\\00000001" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_NR_2147628896_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.NR"
        threat_id = "2147628896"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "File#Error" ascii //weight: 10
        $x_10_2 = "ezkzODdCOEIyLTU1MDgtMTFERS04NzI5LUM1NkY1NUQ4OTU5M30" ascii //weight: 10
        $x_1_3 = "QzpcV0lORE9XU1xzeXN0ZW0zMlx3aW5mYXgyLmRsbA" ascii //weight: 1
        $x_1_4 = "QzpcQXJxdWl2b3MgZGUgcHJvZ3JhbWFzXEFWR1xBVkc4XGF2Z3VwZC5kbGw" ascii //weight: 1
        $x_10_5 = "XFNPRlRXQVJFXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXEV4cGxvcmVyXEJyb3dzZXIgSGVscGVyIE9iamVjdHNc" ascii //weight: 10
        $x_1_6 = "aHR0cDovL3d3dy5tZWJsb3F1ZW91Lm5ldC93aW5mYXgyLmpwZw" ascii //weight: 1
        $x_1_7 = "QzpcV0lORE9XU1xXaW5kbGwuZXhl" ascii //weight: 1
        $x_1_8 = "aHR0cDovL3d3dy5tZWJsb3F1ZW91Lm5ldC9raWNrLmpwZw" ascii //weight: 1
        $x_1_9 = "QzpcV2luZG93c1xTeXN0ZW13aW4uZXhl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_PQ_2147628934_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.PQ"
        threat_id = "2147628934"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "98"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "RootCertFile" ascii //weight: 10
        $x_10_2 = "SSLIOHandlerSocket" ascii //weight: 10
        $x_10_3 = "IdCookieList" ascii //weight: 10
        $x_10_4 = "IdHTTPMethod" ascii //weight: 10
        $x_10_5 = "SQLConnection" ascii //weight: 10
        $x_10_6 = "JPEGImage" ascii //weight: 10
        $x_10_7 = "GIFImage" ascii //weight: 10
        $x_10_8 = "Internet Explorer_Server" ascii //weight: 10
        $x_1_9 = "agricola" ascii //weight: 1
        $x_1_10 = "bpiempresa" ascii //weight: 1
        $x_1_11 = "montepio" ascii //weight: 1
        $x_1_12 = "citi" ascii //weight: 1
        $x_1_13 = "cgdempresa" ascii //weight: 1
        $x_1_14 = "banfi" ascii //weight: 1
        $x_5_15 = {69 6e 76 e1 6c 69 64 6f}  //weight: 5, accuracy: High
        $x_5_16 = "cvv2" ascii //weight: 5
        $x_5_17 = "confirme" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_PD_2147629015_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.PD"
        threat_id = "2147629015"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "46"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_2 = "FindWindowA" ascii //weight: 10
        $x_10_3 = "HKEY_CURRENT_USER\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN\\" wide //weight: 10
        $x_10_4 = {5c 00 4e 00 4f 00 56 00 4f 00 5f 00 50 00 48 00 41 00 52 00 4d 00 49 00 4e 00 47 00 5c 00 [0-48] 2e 00 76 00 62 00 70 00}  //weight: 10, accuracy: Low
        $x_1_5 = "openbank.es" wide //weight: 1
        $x_1_6 = "lacaixa.es" wide //weight: 1
        $x_1_7 = "bancoreal.com.br" wide //weight: 1
        $x_1_8 = "nossacaixa.com.br" wide //weight: 1
        $x_1_9 = "itauprivatebank.com.br" wide //weight: 1
        $x_1_10 = "bradesco.com.br" wide //weight: 1
        $x_1_11 = "unibanco.com.br" wide //weight: 1
        $x_1_12 = "americanas.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_NW_2147629026_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.NW"
        threat_id = "2147629026"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EmbeddedWB http://bsalsa.com/" ascii //weight: 1
        $x_1_2 = "GAROTA-MA.COM" ascii //weight: 1
        $x_1_3 = "INOVANDOOOO..." ascii //weight: 1
        $x_1_4 = "Projetos\\Java\\BHO_NOVO\\uFuncoes.pas" ascii //weight: 1
        $x_1_5 = "https://acesso.uol.com.br/login.html?skin=webmail" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Banker_NZ_2147629027_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.NZ"
        threat_id = "2147629027"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "uploadlanhouse.com.br/uploads/source/winupdate.exe" ascii //weight: 1
        $x_1_2 = "!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP" ascii //weight: 1
        $x_1_3 = {63 6d 64 20 2f 6b 20 63 3a 5c 67 6f 6f 67 6c 65 2d 69 6d 61 67 65 ?? 2e 67 69 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_PE_2147630865_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.PE"
        threat_id = "2147630865"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 69 6e 64 69 72 00 00 ff ff ff ff 1d 00 00 00 a3 9b 90 88 91 93 90 9e 9b 9a 9b df 8f 8d 90 98}  //weight: 1, accuracy: High
        $x_1_2 = {6f 70 65 6e 00 00 00 00 53 56 8b d8 33 d2 8b 83}  //weight: 1, accuracy: High
        $x_1_3 = {8d 4d a8 33 d2 b8 ?? ?? ?? ?? e8 88 fa ff ff 8b 55 a8 58 e8 7f 5c fb ff 8b 45 ac e8 6f 5e fb ff 50 68 ?? ?? ?? ?? 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_PS_2147631714_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.PS"
        threat_id = "2147631714"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "********** CATALUNYA - Thund3rC4sH **********" ascii //weight: 10
        $x_1_3 = "C:A:T:A:L:U:N:Y:A" ascii //weight: 1
        $x_1_4 = "C0D-USU4R101: " ascii //weight: 1
        $x_1_5 = "CLV-4C35501: " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_WZ_2147632261_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.WZ"
        threat_id = "2147632261"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)" ascii //weight: 10
        $x_10_3 = "del delexec.bat" ascii //weight: 10
        $x_10_4 = "insert into clientes" ascii //weight: 10
        $x_1_5 = "justtbbaby.com/js/" ascii //weight: 1
        $x_1_6 = "www.guantanamera.org.br/fotos/" ascii //weight: 1
        $x_1_7 = "catolicanet.net/images/" ascii //weight: 1
        $x_1_8 = "eugenia-jorge.com/js/" ascii //weight: 1
        $x_1_9 = "esperalimentosme.com.br/js" ascii //weight: 1
        $x_1_10 = "lapimepp.com/js/" ascii //weight: 1
        $x_1_11 = "www.rajkotchamber.com/images/" ascii //weight: 1
        $x_1_12 = "www.formandosunidf.com/fotos/" ascii //weight: 1
        $x_1_13 = "www.fundacionasilo.com/Scripts/" ascii //weight: 1
        $x_1_14 = "www.jpx-arq.com/staff/" ascii //weight: 1
        $x_1_15 = "www.pronauti.com/loja/includes/modules/" ascii //weight: 1
        $x_1_16 = "thatsdesign.it/wp-includes/js/" ascii //weight: 1
        $x_1_17 = "www.cinet.it/js/" ascii //weight: 1
        $x_1_18 = "www.asturmed.org/index_archivos/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 11 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_VBO_2147632514_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VBO"
        threat_id = "2147632514"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {65 78 65 2e [0-21] 5c 3a 63}  //weight: 2, accuracy: Low
        $x_2_2 = "\\erawtfoS\\MLKH" ascii //weight: 2
        $x_1_3 = "A%u%t%o%C%o%m%p%l%e%t%e%" ascii //weight: 1
        $x_1_4 = "%m%e%n%s%a%g%e%m%" ascii //weight: 1
        $x_1_5 = "verifique a sua conta" ascii //weight: 1
        $x_1_6 = "senha" ascii //weight: 1
        $x_1_7 = "gmail" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_XE_2147634441_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.XE"
        threat_id = "2147634441"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 8b 4d f8 b2 01 a1 ?? ?? ?? ?? e8 ?? 01 00 00 a3 ?? ?? ?? ?? 8d 55 f4 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f4 50 68 ?? ?? ?? ?? 8d 55 f0 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d f0 b2 01 a1 ?? ?? ?? ?? e8 ?? 01 00 00 a3 ?? ?? ?? ?? 33 c0 5a}  //weight: 1, accuracy: Low
        $x_1_2 = {74 4c 8d 55 f8 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f8 e8 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8d 55 f4 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f4 e8 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 33 c0 5a}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 f0 50 8d 55 e8 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 e8 5a e8 ?? ?? ?? ?? 85 c0 0f 8f ?? 00 00 00 8d 45 e0 8b 53 04 e8 ?? ?? ?? ?? 8b 45 e0 8d 55 e4 e8 ?? ?? ?? ?? 8b 45 e4 50 8d 55 dc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 dc 5a e8 ?? ?? ?? ?? 85 c0 (0f|7f)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_XF_2147637586_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.XF"
        threat_id = "2147637586"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 37 85 db 74 15 8a 02 3c 61 72 06 3c 7a 77 02 2c 20 88 06 42 46 4b}  //weight: 10, accuracy: High
        $x_1_2 = "Erro ao abrir arquivo ou pasta" ascii //weight: 1
        $x_1_3 = ".com.br/fotos" wide //weight: 1
        $x_1_4 = "C:\\WINDOWS\\WindowsUpdate.exe" wide //weight: 1
        $x_5_5 = "57C3A854E70362ED71FA7D9DB225A35F87CB7AFE25C879D909002BEE17" ascii //weight: 5
        $x_7_6 = "48E90B2ED23F5DC773D863D57BE5639F4490BB143F303350B6D372AF54DA6699311536E756E90ED50838D777A64734296EDF3AF73BF8" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_7_*) and 1 of ($x_5_*))) or
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_QQ_2147637620_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.QQ"
        threat_id = "2147637620"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 62 63 6b 2e 62 63 6b [0-32] 5c [0-16] 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {44 61 64 6f 73 20 64 65 20 61 70 6c 69 63 61 74 69 76 6f 73 5c [0-16] 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c [0-16] 55 53 45 52 50 52 4f 46 49 4c 45 [0-16] 70 70 44 61 74 61 5c [0-16] 57 65 62 4d 61 6f}  //weight: 1, accuracy: Low
        $x_1_3 = {85 db 7c 65 8b 45 ?? c1 e0 ?? 03 d8 89 5d ?? 83 c7 ?? 83 ff 08 7c 48 83 ef 08 8b cf}  //weight: 1, accuracy: Low
        $x_1_4 = {85 db 7e 2b be 01 00 00 00 8d 45 ?? 8b d7 52 8b 55 ?? 8a 54 32 ?? 59 2a d1 f6 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Banker_QW_2147638351_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.QW"
        threat_id = "2147638351"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\Browser Helper Objects\\" ascii //weight: 1
        $x_3_2 = "Por favor, preencha corretamente o campo \"Senha Eletr" ascii //weight: 3
        $x_3_3 = "E013D26596F669934D49984F3846A8A6B" ascii //weight: 3
        $x_2_4 = "Image3Click" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_RB_2147638846_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.RB"
        threat_id = "2147638846"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "300"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "sdfjnldfkgnds" ascii //weight: 100
        $x_100_2 = "dfgdfgdfg.exe" wide //weight: 100
        $x_100_3 = "df;mgsdfongsodfngolsnfdkgolsdnfgosbfdogjsn" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_RC_2147638917_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.RC"
        threat_id = "2147638917"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "insertAdjacentHTML" ascii //weight: 1
        $x_2_2 = "alipay.com/ebank/payment_gateway.htm" ascii //weight: 2
        $x_2_3 = "<input name=\"bankID\" type=\"hidden\" value=\"" ascii //weight: 2
        $x_1_4 = "taskkill /f /im" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_XG_2147639017_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.XG"
        threat_id = "2147639017"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 8b 4d 08 81 f1 ?? ?? 00 00 3b c1 75 08 05 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "SELECT * FROM AntiVirusProduct" wide //weight: 1
        $x_1_3 = "ROOT\\SecurityCenter2" wide //weight: 1
        $x_2_4 = "inject_setting" ascii //weight: 2
        $x_2_5 = "inject_after_keyword" ascii //weight: 2
        $x_2_6 = "inject_before_keyword" ascii //weight: 2
        $x_1_7 = "bc00595440e801f8a5d2a2ad13b9791b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_XH_2147639097_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.XH"
        threat_id = "2147639097"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 50 8b 45 fc 50 6a 07 6a 00 68 ?? ?? ?? ?? 8b 43 04 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "\\??\\c:\\WINDOWS\\rapportClean1.txt" ascii //weight: 1
        $x_1_3 = "!\\??\\C:\\Program Files\\Trusteer\\Rapport\\js\\config.js" ascii //weight: 1
        $x_1_4 = {50 65 6e 64 69 6e 67 46 69 6c 65 52 65 6e 61 6d 65 4f 70 65 72 61 74 69 6f 6e 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_RQ_2147641127_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.RQ"
        threat_id = "2147641127"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 06 03 d8 89 ?? ?? 83 c7 06 83 ff 08 7c ?? 83 ef 08 8b cf 8b ?? ?? d3 eb 8b cf b8 01 00 00 00 d3 e0 8b c8 8b ?? ?? 99 f7 f9}  //weight: 1, accuracy: Low
        $x_1_2 = "taskkill /im msnmsgr.exe /f" ascii //weight: 1
        $x_1_3 = "mail.terra.com.br" ascii //weight: 1
        $x_1_4 = "senha" ascii //weight: 1
        $x_1_5 = "- PayPal -" ascii //weight: 1
        $x_1_6 = "Seja bem-vindo(a) ao Facebook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Banker_SC_2147642208_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.SC"
        threat_id = "2147642208"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 00 6e 00 66 00 65 00 63 00 74 00 20 00 [0-2] 2e 00 [0-2] 72 00 65 00 6c 00 65 00 61 00 73 00 65 00 20 00 42 00 44 00 3a 00 20 00 20 00 2d 00}  //weight: 2, accuracy: Low
        $x_1_2 = "C:\\windows\\dscprog.txt" wide //weight: 1
        $x_1_3 = "AtualizacaoBra" wide //weight: 1
        $x_1_4 = "InfoDsc:  - " wide //weight: 1
        $x_1_5 = "- TABELA!!!!! BDeskao" wide //weight: 1
        $x_1_6 = "essencial para manter ativo a sua conta.." wide //weight: 1
        $x_2_7 = {75 28 8d 55 ?? 8b 45 ?? e8 ?? ?? ?? ?? 8b 4d ?? 8b 45 ?? 8b 80 ?? ?? ?? ?? 05 98 00 00 00 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? eb 46}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_XO_2147642522_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.XO"
        threat_id = "2147642522"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 68 58 4d 56 bb 65 d4 85 86 b9 0a 00 00 00 66 ba 58 56 ed}  //weight: 1, accuracy: High
        $x_2_2 = {8b 55 08 8b 7d 10 0f be 04 13 2b c7 43 88 44 0d ?? 41 83 f9 04 7c e9}  //weight: 2, accuracy: Low
        $x_1_3 = {64 a1 30 00 00 00 8b 40 0c 8b 40 0c 8d ?? ?? ?? ?? 00 66 c7 40 24 60 00 89 ?? 28}  //weight: 1, accuracy: Low
        $x_1_4 = "</B><SPAN id=bank-name>" ascii //weight: 1
        $x_1_5 = "BANK=%s&QIAN=%s&ALIPAYNAME=%s&ALIPAYVER=%s" ascii //weight: 1
        $x_1_6 = "%s/PayToMe/TB_Pay.Asp?nFlag=0&UserName=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_SF_2147642577_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.SF"
        threat_id = "2147642577"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "E40637E80E3820C6628AB3AA5C87B567985A" ascii //weight: 4
        $x_4_2 = " (N_PC , N_NOME , DT_DATA , TXT_CT) VALUES (:PC , :NOME , :DATA , :CT) " ascii //weight: 4
        $x_2_3 = "tm_gebb01Timer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_SL_2147643147_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.SL"
        threat_id = "2147643147"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {94 14 85 c9 74 0c 39 08 75 08 89 cf 8b 41 fc 4a eb 02 31 c0 8b 4c 94 14 85 c9 74 0b}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e0 06 03 d8 89 ?? ?? 83 c7 06 83 ff 08 7c ?? 83 ef 08 8b cf 8b ?? ?? d3 eb 8b cf b8 01 00 00 00 d3 e0 8b c8 8b ?? ?? 99 f7 f9}  //weight: 1, accuracy: Low
        $x_1_3 = {73 61 6e 6f 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 75 73 65 72 6e 61 6d 65 70 61 73 73 77 6f 72 64 07 69 64 73 6f 63 6b 73}  //weight: 1, accuracy: High
        $x_1_4 = "bradesco" ascii //weight: 1
        $x_1_5 = "Baixando de" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_SO_2147643751_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.SO"
        threat_id = "2147643751"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {94 14 85 c9 74 0c 39 08 75 08 89 cf 8b 41 fc 4a eb 02 31 c0 8b 4c 94 14 85 c9 74 0b}  //weight: 1, accuracy: High
        $x_1_2 = {73 61 6e 6f 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 75 73 65 72 6e 61 6d 65 70 61 73 73 77 6f 72 64 07 69 64 73 6f 63 6b 73}  //weight: 1, accuracy: High
        $x_1_3 = ".com.br" ascii //weight: 1
        $x_1_4 = "caminho" ascii //weight: 1
        $x_1_5 = "praquem=" ascii //weight: 1
        $x_1_6 = "logaa.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_SW_2147644336_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.SW"
        threat_id = "2147644336"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {94 14 85 c9 74 0c 39 08 75 08 89 cf 8b 41 fc 4a eb 02 31 c0 8b 4c 94 14 85 c9 74 0b}  //weight: 1, accuracy: High
        $x_1_2 = "INOVANDOOOO..." ascii //weight: 1
        $x_1_3 = "projects\\novobho" ascii //weight: 1
        $x_1_4 = {6d 61 69 6c 61 67 65 6e 74 [0-27] 68 65 6c 6f 6e 61 6d 65 [0-27] 75 73 65 65 68 6c 6f}  //weight: 1, accuracy: Low
        $x_1_5 = "banco" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Banker_SY_2147644453_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.SY"
        threat_id = "2147644453"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {94 14 85 c9 74 0c 39 08 75 08 89 cf 8b 41 fc 4a eb 02 31 c0 8b 4c 94 14 85 c9 74 0b}  //weight: 1, accuracy: High
        $x_1_2 = "mando baixa" ascii //weight: 1
        $x_1_3 = "SENHA=" ascii //weight: 1
        $x_1_4 = "picasacheck" ascii //weight: 1
        $x_1_5 = ".com.br" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_VV_2147645555_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VV"
        threat_id = "2147645555"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4b 70 ba ?? ?? ?? ?? 8b c6 e8 ee d3 ff ff dd 43 40 d8 1d ?? ?? ?? ?? df e0 9e 76 1f ff 73 44 ff 73 40 8d 55 f8 33 c0 e8 00 62 ff ff 8b 4d f8 ba ?? ?? ?? ?? 8b c6 e8 c1 d3 ff ff 8b 7b 20 85 ff 75 0a 83 7b 1c 00 0f 84 88 00 00 00 83 7b 1c 00}  //weight: 2, accuracy: Low
        $x_1_2 = "Keylogger of Banker" ascii //weight: 1
        $x_1_3 = "Keylogger_PayPal" ascii //weight: 1
        $x_1_4 = "x-coder-x" ascii //weight: 1
        $x_1_5 = "Senha" ascii //weight: 1
        $x_1_6 = "Device\\varsao" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_XY_2147646445_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.XY"
        threat_id = "2147646445"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 72 61 71 75 65 6d 3d [0-32] 40 (68 6f 74 6d 61 69 6c 2e 63|67 6d 61 69 6c 2e 63)}  //weight: 1, accuracy: Low
        $x_1_2 = "Senha internet" ascii //weight: 1
        $x_1_3 = "titulo=::" ascii //weight: 1
        $x_1_4 = "o teclado virtual" ascii //weight: 1
        $x_1_5 = "injetel.com.br" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Banker_YB_2147646742_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.YB"
        threat_id = "2147646742"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e 22 20 2f 76 20 22 (43 49|56 49) 22 20 2f 64 20 43 3a 5c 55 6e 6e 69 73 74 74 61 6c 6c 2e 65 78 65 20 2f 74 20 22 52 45 47 5f 53 5a 22 20 2f 66 00}  //weight: 1, accuracy: Low
        $x_1_2 = {4f 6e 65 43 6f 70 79 4d 75 74 65 78 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 65 73 73 61 67 65 3d 69 6e 66 65 63 74 61 64 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ZC_2147647080_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ZC"
        threat_id = "2147647080"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Internet Settings\\Zones\\3" ascii //weight: 2
        $x_2_2 = "{A8A88C49-5EB2-4990-A1A2-0876022C854F}" ascii //weight: 2
        $x_2_3 = {00 4a 5f 61 75 74 68 53 75 62 6d 69 74 00}  //weight: 2, accuracy: High
        $x_2_4 = "passport_51_submit" ascii //weight: 2
        $x_2_5 = "inpour_channel_no" ascii //weight: 2
        $x_1_6 = "https://cashier.alipay.com/standard/gateway/ebankPay.htm" ascii //weight: 1
        $x_1_7 = ".alipay.com/standard/payment/cashier.htm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_YL_2147647358_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.YL"
        threat_id = "2147647358"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "LoginMailEXX0089" ascii //weight: 5
        $x_1_2 = "rede_de_dados" ascii //weight: 1
        $x_1_3 = "WWW_GetWindowInfo" ascii //weight: 1
        $x_1_4 = "brasilinstrumental.com.br/envioX.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_YQ_2147647652_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.YQ"
        threat_id = "2147647652"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "titulo=Registradora Eletronica:" wide //weight: 2
        $x_2_2 = ":81/images/" wide //weight: 2
        $x_2_3 = "User...." wide //weight: 2
        $x_2_4 = "Correo...." wide //weight: 2
        $x_1_5 = "BANKINTERCOM" wide //weight: 1
        $x_1_6 = "BANCOPOPULARE" wide //weight: 1
        $x_1_7 = "PORTALLACAIXA" wide //weight: 1
        $x_1_8 = "WESTERNUNION" wide //weight: 1
        $x_1_9 = "CAIXAPENEDES" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_YR_2147647655_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.YR"
        threat_id = "2147647655"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {53 61 66 65 20 6f 66 20 74 68 65 20 73 6f 66 74 77 61 72 65 20 73 65 63 75 72 69 74 79 00}  //weight: 5, accuracy: High
        $x_5_2 = {53 65 67 75 72 69 64 61 64 00 00 00 54 65 6e 64 72}  //weight: 5, accuracy: High
        $x_2_3 = {66 6f 74 75 69 6e 68 6f 00}  //weight: 2, accuracy: High
        $x_2_4 = {62 61 69 78 6f 43 6c 69 63 6b 07 54 6c 69 67 61 64 6f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_YX_2147647830_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.YX"
        threat_id = "2147647830"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 62 70 00 08 00 ff ff ff ff 03 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {67 62 69 65 00 08 00 ff ff ff ff 04 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 3f 3f 5c 00 08 00 ff ff ff ff 04 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {73 63 70 00 08 00 ff ff ff ff 03 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {73 73 68 69 62 00 08 00 ff ff ff ff 05 00 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 ?? 7d 03 46 eb 05 be 01 00 00 00 8b 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 44 30 ff 33 d8 8d 45 ?? 50 89 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Banker_YT_2147647906_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.YT"
        threat_id = "2147647906"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {0f b7 54 7a fe 8b 4d fc 0f b7 4c 71 fe 66 33 d1 e8}  //weight: 6, accuracy: High
        $x_1_2 = {eb ea 6a 03 6a 00 6a 00 8d 55 e0 a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? ?? ?? 8b 45 e0 e8 ?? ?? ?? ?? 50 6a 00 8b 45 fc e8 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_3 = "CfOISABOgA" wide //weight: 1
        $x_1_4 = "Y FMst~sF" wide //weight: 1
        $x_1_5 = "X{tyu:I{tn{t~" wide //weight: 1
        $x_1_6 = "uhqon:7:vu}st" wide //weight: 1
        $x_1_7 = "Mst~umi:Vs" wide //weight: 1
        $x_1_8 = "witwi}h" wide //weight: 1
        $x_1_9 = "n:_bjvuh" wide //weight: 1
        $x_1_10 = "Internet | Modo Protegido: Ativado" wide //weight: 1
        $x_1_11 = {57 69 6e 64 6f 77 73 4c 69 76 65 3a 6e 61 6d 65 3d 2a ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 69 6e 66 6f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 70 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_ZG_2147648048_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ZG"
        threat_id = "2147648048"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 5c 78 fe 33 5d e4 3b 5d e8 7f 0b 81 c3 ff 00 00 00 2b 5d e8 eb 03 2b 5d e8}  //weight: 1, accuracy: High
        $x_1_2 = "\\drivers\\innimates" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ZG_2147648048_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ZG"
        threat_id = "2147648048"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "smtpauthenticate" wide //weight: 2
        $x_1_2 = "bradesco.com.br" wide //weight: 1
        $x_1_3 = "caixa.com.b" wide //weight: 1
        $x_1_4 = "real.com.br" wide //weight: 1
        $x_1_5 = "www.unibanco.com.br" wide //weight: 1
        $x_1_6 = "itau.com.br" wide //weight: 1
        $x_1_7 = "orkut.com" wide //weight: 1
        $x_1_8 = "hotmail.com" wide //weight: 1
        $x_1_9 = "youtube.com/watch" wide //weight: 1
        $x_1_10 = "BaixarArquivos" ascii //weight: 1
        $x_1_11 = "MonitoraEnvioDeDados" ascii //weight: 1
        $x_1_12 = "txtSenhaFtp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_ZW_2147648369_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ZW"
        threat_id = "2147648369"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "bradesco.com.br" wide //weight: 1
        $x_1_2 = "Digite sua senha" ascii //weight: 1
        $x_1_3 = {61 00 67 00 65 00 6e 00 63 00 69 00 61 00 [0-32] 76 00 61 00 6c 00 75 00 65 00 [0-16] 63 00 6f 00 6e 00 74 00 61 00 [0-16] 64 00 61 00 63 00 [0-16] 73 00 65 00 6e 00 68 00 61 00 [0-16] 43 00 6f 00 6e 00 74 00 61 00 69 00 6e 00 65 00 72 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_E_2147648474_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.gen!E"
        threat_id = "2147648474"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@hotmail.com" ascii //weight: 1
        $x_1_2 = "@yahoo.com" ascii //weight: 1
        $x_1_3 = "Senha" ascii //weight: 1
        $x_1_4 = "MAC:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Banker_ZZ_2147648547_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ZZ"
        threat_id = "2147648547"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tecnologic\\Downloads\\novoexe\\Project1.vbp" wide //weight: 1
        $x_1_2 = "3O Horas!" ascii //weight: 1
        $x_1_3 = "VersaoAtual" ascii //weight: 1
        $x_1_4 = "cadastro" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AAF_2147648827_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AAF"
        threat_id = "2147648827"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 03 f0 66 69 c6 cd b1 66 05 ff cf 8b f0 80 c3 02}  //weight: 2, accuracy: High
        $x_2_2 = {70 72 61 71 75 65 6d 3d [0-32] 40 (68 6f 74 6d 61 69 6c 2e 63|67 6d 61 69 6c 2e 63)}  //weight: 2, accuracy: Low
        $x_1_3 = "netsh firewall add allowedprogram" ascii //weight: 1
        $x_1_4 = "2e3c3651-b19c-4dd9-a979-901ec3e930af" ascii //weight: 1
        $x_1_5 = "SELECT * FROM controle_dep_comunicacao WHERE N_MCADDRESS ='" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AAG_2147648828_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AAG"
        threat_id = "2147648828"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 56 61 6c 75 65 73 20 3d 20 41 72 72 61 79 28 26 48 34 36 2c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2c 26 48 36 38 2c 26 48 37 34 2c 26 48 37 34 2c 26 48 37 30 2c 26 48 33 61 2c 26 48 32 66 2c 26 48 32 66}  //weight: 1, accuracy: Low
        $x_1_2 = "user_pref(\"network.proxy.autoconfig_url\", \"http://" wide //weight: 1
        $x_1_3 = {2f 63 20 22 77 73 63 72 69 70 74 2e 65 78 65 20 2f 42 20 22 25 75 73 65 72 70 72 6f 66 69 6c 65 25 5c [0-8] 2e 76 62 73 22 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AAM_2147649093_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AAM"
        threat_id = "2147649093"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 23 78 65 72 2f 2f 3a 70 23 74 74 68 00 ?? ?? ?? ?? ?? ?? ?? [0-3] 00 5c 76 [0-1] 65 [0-1] 72 73 [0-1] 61 6f [0-1] 2e 64 [0-1] 6c 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_VBW_2147649584_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VBW"
        threat_id = "2147649584"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 46 00 20 00 2f 00 49 00 4d 00 20 00 66 00 69 00 72 00 65 00 66 00 6f 00 78 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {56 69 76 6f 20 42 72 61 73 69 6c 20 4d 4d 53 05}  //weight: 1, accuracy: High
        $x_1_3 = {44 69 73 63 61 64 6f 72 20 43 6c 61 72 6f 0d 00 56 49 56 4f 20 49 4e 54 45 52 4e 45 54 0f 00 43 6f 6e 65 78 e3}  //weight: 1, accuracy: High
        $x_1_4 = "Safety.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AAQ_2147649676_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AAQ"
        threat_id = "2147649676"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "subject=[I][n][f][e][c][t]" wide //weight: 3
        $x_1_2 = {52 45 47 20 41 44 44 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e [0-32] 49 50 41 22 20 2f 64 20 43 3a 5c 55 6e 6e 69 73 74 74 61 6c 6c 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {66 00 69 00 6c 00 65 00 3a 00 2f 00 2f 00 43 00 3a 00 5c 00 [0-10] 2e 00 70 00 61 00 63 00}  //weight: 1, accuracy: Low
        $x_1_4 = "AutoConfigURL" wide //weight: 1
        $x_1_5 = {2f 00 67 00 68 00 2e 00 70 00 68 00 70 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AAS_2147649952_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AAS"
        threat_id = "2147649952"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2f 65 6e 76 69 61 64 6f 72 2e 70 68 70 00}  //weight: 2, accuracy: High
        $x_2_2 = {74 6f 70 6f 3d 00 00 00 ff ff}  //weight: 2, accuracy: High
        $x_2_3 = {6d 73 67 3d 00 00 00 00 ff ff}  //weight: 2, accuracy: High
        $x_1_4 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 69 74 2e 62 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_5 = {49 74 61 75 62 61 6e 6b 6c 69 6e 65 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 69 74 61 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {41 74 75 61 6c 69 7a 61 63 61 6f 42 72 61 00}  //weight: 1, accuracy: High
        $x_1_8 = {5c 64 73 63 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {5c 64 73 63 70 72 6f 67 2e 74 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AAV_2147650002_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AAV"
        threat_id = "2147650002"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 70 64 61 74 65 2f 72 62 2e 70 68 70 3f 68 65 6c 6c 6f 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 69 6e 66 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_3 = "user_pref(\"network.proxy.autoconfig_url\"" ascii //weight: 1
        $x_1_4 = "Erase \"%s\"" ascii //weight: 1
        $x_1_5 = "Meu PHARM\\EXE\\PerfecT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Banker_AAX_2147650235_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AAX"
        threat_id = "2147650235"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Teclado virtual desabilitado, por favor utilize seu teclado convencional" ascii //weight: 10
        $x_1_2 = "Banco Santander Empresarial" ascii //weight: 1
        $x_1_3 = "InternetBanking" ascii //weight: 1
        $x_1_4 = "includes/js/theme.php" ascii //weight: 1
        $x_1_5 = "WSASetBlockingHook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AAZ_2147650278_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AAZ"
        threat_id = "2147650278"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/get.asp?ag=" wide //weight: 1
        $x_1_2 = "&campo10=" wide //weight: 1
        $x_1_3 = "COMPUTERNAME" wide //weight: 1
        $x_1_4 = {b8 04 00 02 80 89 0b 8b 4d bc 52 89 4b 04 89 43 08 8b 45 c4 89 43 0c ff 56 34 85 c0 db e2 7d 12}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ABA_2147650279_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ABA"
        threat_id = "2147650279"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mac: Procurando..." wide //weight: 1
        $x_1_2 = "Nome do computador: Procurando..." wide //weight: 1
        $x_1_3 = "/www.dentistaenqueretaro.com/" wide //weight: 1
        $x_1_4 = {0e 54 4b 65 79 50 72 65 73 73 45 76 65 6e 74}  //weight: 1, accuracy: High
        $x_1_5 = {8b c0 33 d2 66 33 10 8b 08 c1 e9 10 66 33 d1 66 33 50 04 66 33 50 06 66 33 50 08 66 33 50 0a 66 33 50 0c 66 33 50 0e 66 33 50 10 8b 40 10 c1 e8 10 66 33 d0 8b c2 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ABG_2147650719_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ABG"
        threat_id = "2147650719"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 85 ?? ff ff ff e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 8b ?? 6a 01}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 07 b2 02 e8 ?? ?? ff ff 8b 45 fc 80 78 5b 00 74 ?? 8b 45 fc 8b 40 44 80 b8 ?? ?? 00 00 01 ?? ?? 8b ?? fc}  //weight: 1, accuracy: Low
        $x_1_3 = {0e 54 4b 65 79 50 72 65 73 73 45 76 65 6e 74}  //weight: 1, accuracy: High
        $x_1_4 = "Silent" ascii //weight: 1
        $x_1_5 = "password" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ABG_2147650719_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ABG"
        threat_id = "2147650719"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {eb 05 be 01 00 00 00 8b 45 0c 0f b6 44 30 ff 33 c3 89 45 e8 3b 7d e8 7c 0f 8b 45 e8 05 ff 00 00 00 2b c7 89 45 e8 eb 03 29 7d e8 8d 45 bc 8b 55 e8 e8}  //weight: 10, accuracy: High
        $x_1_2 = {21 73 72 63 3d 22 68 74 74 70 73 3a 2f 2f 62 72 61 64 65 73 63 6f 6e 65 74 65 6d 70 72 65 73 61 2e 63 06 21 6f 6d 2e 62 72 2f}  //weight: 1, accuracy: High
        $x_1_3 = {6f 72 6b 75 74 2e 63 6f 6d 2f 69 6d 67 2f 67 77 74 2f 69 6e 70 75 74 2d 62 74 6e 2d 68 74 6d 6c 2e 70 6e 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {69 6e 73 65 72 74 73 71 6c 2e 70 68 70 3f 00}  //weight: 1, accuracy: High
        $x_1_5 = {75 70 64 61 74 65 73 71 6c 2e 70 68 70 3f 00}  //weight: 1, accuracy: High
        $x_1_6 = "/ppsecure/sha1auth.srf" wide //weight: 1
        $x_1_7 = {5f 53 43 52 49 50 54 5f 50 41 53 54 45 5f 55 52 4c 41 43 54 49 4f 4e 5f 49 46 5f 50 52 4f 4d 50 54 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_ABJ_2147650978_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ABJ"
        threat_id = "2147650978"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4b 70 ba ?? ?? ?? ?? 8b c6 e8 ee d3 ff ff dd 43 40 d8 1d ?? ?? ?? ?? df e0 9e 76 1f ff 73 44 ff 73 40 8d 55 f8 33 c0 e8 00 62 ff ff 8b 4d f8 ba ?? ?? ?? ?? 8b c6 e8 c1 d3 ff ff 8b 7b 20 85 ff 75 0a 83 7b 1c 00 0f 84 88 00 00 00 83 7b 1c 00}  //weight: 10, accuracy: Low
        $x_1_2 = "senha" ascii //weight: 1
        $x_1_3 = "Se#nh#a Car#ta#o" ascii //weight: 1
        $x_1_4 = "banc#o do" ascii //weight: 1
        $x_1_5 = "up@.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_ABM_2147651283_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ABM"
        threat_id = "2147651283"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f8 8b 55 e4 0f b6 44 10 ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 f0 7d 03 46 eb 05 be 01 00 00 00 8b 45 e8 0f b6 44 30 ff 33 d8}  //weight: 1, accuracy: High
        $x_1_2 = {43 08 6e 68 67 64 68 49 59 74 00 48 69 53 48 49 79 53 43 00}  //weight: 1, accuracy: High
        $x_1_3 = {45 33 37 32 43 31 35 44 38 30 41 42 34 32 46 43 32 32 44 42 41 31 42 45 36 45 41 31 35 30 33 32 33 35 32 43 30 41 33 37 39 46 38 42 44 42 43 33 36 35 46 38 33 44 45 37 31 42 36 39 39 34 35 42 38 34 32 43 30 38 33 37 45 42 30 36 32 34 43 34 37 32 38 45 33 42 41 35 38 34 00}  //weight: 1, accuracy: High
        $x_1_4 = "https://login.live.com/login.srf?wa=wsignin1.0&rpsnv=11&ct=1306905729&rver=6.1.6206.0&wp=MBI&wreply=http:%2F%2Fmail.live.com%" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ABP_2147651418_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ABP"
        threat_id = "2147651418"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4b 70 ba ?? ?? ?? ?? 8b c6 e8 ?? ?? ?? ?? dd 43 40 d8 1d ?? ?? ?? ?? df e0 9e 76 1f ff 73 44 ff 73 40 8d 55 f8 33 c0 e8 00 62 ff ff 8b 4d f8 ba}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 44 10 ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 ?? 7d 03 46 eb 05 be 01 00 00 00 8b 45 ?? 0f b6 44 30 ff 33 d8 8d 45 ?? 50 89 5d}  //weight: 1, accuracy: Low
        $x_1_3 = {41 67 65 6e 63 69 61 [0-33] 43 6f 6e 74 61 [0-80] 53 65 6e 68 61}  //weight: 1, accuracy: Low
        $x_1_4 = "silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ABQ_2147651420_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ABQ"
        threat_id = "2147651420"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 b2 02 e8 ?? ?? ff ff 8b 45 fc 80 78 5b 00 74 ?? 8b 45 fc 8b 40 44 80 b8 ?? ?? 00 00 01 ?? ?? 8b ?? fc}  //weight: 1, accuracy: Low
        $x_1_2 = {69 6e 76 e1 6c 69 64 6f}  //weight: 1, accuracy: High
        $x_1_3 = "edtsenha" ascii //weight: 1
        $x_1_4 = "Windows Live Messenger!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ABR_2147651599_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ABR"
        threat_id = "2147651599"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 07 b2 02 e8 ?? ?? ff ff 8b 45 fc 80 78 5b 00 74 ?? 8b 45 fc 8b 40 44 80 b8 ?? ?? 00 00 01 ?? ?? 8b ?? fc}  //weight: 2, accuracy: Low
        $x_1_2 = "Silent" ascii //weight: 1
        $x_1_3 = "*up*.*ex*e" ascii //weight: 1
        $x_1_4 = "senha" ascii //weight: 1
        $x_1_5 = "Bra#des#co" ascii //weight: 1
        $x_1_6 = "bradesco internet banking" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_ABU_2147651713_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ABU"
        threat_id = "2147651713"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f8 a1 30 2f 47 00 8b 08 ff 51 38 8d 45 f0 50 8b 0d 30 2f 47 00 ba ?? ?? ?? ?? 8b 83 00 03 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {73 75 62 6a 65 63 74 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6d 65 73 73 61 67 65 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_3 = "Teclado virtual desabilitado, por favor utilize seu teclado" ascii //weight: 1
        $x_1_4 = {41 74 75 61 6c 69 7a 61 6e 64 6f 20 2d 20 45 74 61 70 61 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ABT_2147651715_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ABT"
        threat_id = "2147651715"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "79FA0F13131D363EC5" ascii //weight: 2
        $x_2_2 = "0606181E28AA283019" ascii //weight: 2
        $x_2_3 = "AEB76F934FF11D17362DD81A33" ascii //weight: 2
        $x_1_4 = "668391BA6089AA5DE91534E10B74A65094" ascii //weight: 1
        $x_1_5 = "AA46CC7FA84BCA06251AC476A6" ascii //weight: 1
        $x_1_6 = "DF63E676FD081D192FCA46DF6" ascii //weight: 1
        $x_1_7 = "C648CB59D86D868086939" ascii //weight: 1
        $x_1_8 = "42C545D050DA68EE75808B929A9" ascii //weight: 1
        $x_1_9 = "E86AE97BFA0F242238C54DD059D36" ascii //weight: 1
        $x_1_10 = "AEB0A846C373A25F80BF6593FF29C" ascii //weight: 1
        $x_1_11 = "CC5D3FD57BAC5781B06DC76698B66899" ascii //weight: 1
        $x_1_12 = "1FC679AE5BD04632DC0F30D775" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_ACB_2147651802_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ACB"
        threat_id = "2147651802"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 63 00 70 00 4d 00 49 00 42 00 2e 00 64 00 6c 00 6c 00 [0-85] 5c 00 41 00 56 00 47 00 31 00 30 00 5c 00 61 00 76 00 67 00 74 00 72 00 61 00 79 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 61 00 73 00 5c 00 41 00 56 00 47 00 5c 00 41 00 56 00 47 00 38 00 5c 00 61 00 76 00 67 00 75 00 70 00 64 00 2e 00 65 00 78 00 65 00 [0-96] 5c 00 41 00 76 00 61 00 73 00 74 00 35 00 5c 00 56 00 69 00 73 00 74 00 68 00 55 00 70 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 00 47 00 62 00 50 00 6c 00 75 00 67 00 69 00 6e 00 5c 00 47 00 62 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ACC_2147651818_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ACC"
        threat_id = "2147651818"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "order by NM_ID desc" ascii //weight: 1
        $x_1_2 = {48 6f 73 74 3d 73 6d 74 70 [0-1] 2e 75 6f 6c 2e 63 6f 6d 2e 62 72}  //weight: 1, accuracy: Low
        $x_1_3 = "loginbotoes:botaoAvancar" ascii //weight: 1
        $x_1_4 = "/ibpflogin/identificacao.jsf" ascii //weight: 1
        $x_1_5 = "onClick=\"enviaTudo();\" " ascii //weight: 1
        $x_1_6 = "S-E-R-A-S-A" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Banker_ACF_2147651909_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ACF"
        threat_id = "2147651909"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 00 00 00 62 ?? 72 ?? 61 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6f ?? 6d}  //weight: 1, accuracy: Low
        $x_1_2 = {28 00 00 00 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 ?? 7e ?? ?? ?? ?? ?? 47 ?? 62 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {50 00 00 00 5c ?? ?? ?? ?? ?? ?? ?? 67 ?? ?? ?? ?? ?? ?? ?? 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ACK_2147652174_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ACK"
        threat_id = "2147652174"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[ M0N3Y ]" wide //weight: 1
        $x_1_2 = {2f 00 72 00 65 00 64 00 73 00 6e 00 6f 00 77 00 2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 70 00 68 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {4d 00 34 00 63 00 20 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 3a 00 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 00 20 00 64 00 61 00 20 00 4e 00 65 00 74 00 20 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 3a 00 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {6f 00 20 00 63 00 6f 00 6d 00 20 00 6f 00 20 00 53 00 65 00 72 00 76 00 69 00 64 00 6f 00 72 00 2c 00 20 00 74 00 65 00 6e 00 74 00 65 00 20 00 6e 00 6f 00 76 00 61 00 6d 00 65 00 6e 00 74 00 65 00 20 00 6d 00 61 00 69 00 73 00 20 00 74 00 61 00 72 00 64 00 65 00 2e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Banker_ACL_2147652185_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ACL"
        threat_id = "2147652185"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\11.txt" ascii //weight: 2
        $x_2_2 = "OMHjQMukOc5q" ascii //weight: 2
        $x_3_3 = "TT_F_U_C" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ACN_2147652313_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ACN"
        threat_id = "2147652313"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {7e 5e 89 45 f0 bf 01 00 00 00 8d 45 f4 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 8a 54 3a ff 8b 4d fc 8a 4c 31 ff 32 d1}  //weight: 10, accuracy: Low
        $x_1_2 = "leocaloteiro" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ACR_2147652514_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ACR"
        threat_id = "2147652514"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 40 0c 20 4e 00 00 8d 4d}  //weight: 1, accuracy: High
        $x_1_2 = {ba 90 80 84 2d 8b 45}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 fc 91 be 32 b9 8d 45}  //weight: 1, accuracy: High
        $x_1_4 = {c7 43 2c 20 1c 00 00 a1 05 00 e8}  //weight: 1, accuracy: Low
        $x_1_5 = {c7 40 0c 98 3a 00 00 8d 4d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanSpy_Win32_Banker_ACS_2147652582_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ACS"
        threat_id = "2147652582"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GsnXTcKWRcyWTk5iQMHXBW" ascii //weight: 1
        $x_1_2 = "=_NextPart_2relrfksadvnqindyw3nerasdf" ascii //weight: 1
        $x_1_3 = {41 4c 4c 3a 21 41 44 48 3a 52 43 34 2b 52 53 41 3a 2b 48 49 47 48 3a 2b 4d 45 44 49 55 4d 3a 2b 4c 4f 57 3a 2b 53 53 4c 76 32 3a 2b 45 58 50 00}  //weight: 1, accuracy: High
        $x_1_4 = {7c 65 8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 48 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80 79 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_VBY_2147652605_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VBY"
        threat_id = "2147652605"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 f4 7d 03 46 eb 05 be 01}  //weight: 2, accuracy: High
        $x_2_2 = {89 45 f4 33 f6 bb 00 01 00 00 8d 55 dc b8}  //weight: 2, accuracy: High
        $x_3_3 = {78 73 65 72 76 69 63 65 78 00}  //weight: 3, accuracy: High
        $x_1_4 = {5c 76 65 72 73 61 6f 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {67 6d 61 69 6c 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {6d 73 6e 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_7 = "caixaebanking" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_F_2147653084_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.gen!F"
        threat_id = "2147653084"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 5c 78 fe 33 5d ?? 3b 5d ?? 7f 0b 81 c3 ff 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "pedrocacarneiro@gmail.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ADH_2147653222_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ADH"
        threat_id = "2147653222"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MsShutt_" ascii //weight: 1
        $x_1_2 = "\\Software\\Alx\\Config\\" ascii //weight: 1
        $x_1_3 = "M.@.5.7.3.R..C.@.R.D" ascii //weight: 1
        $x_1_4 = "Senha Cartao....:" ascii //weight: 1
        $x_1_5 = "H.5.B.C" ascii //weight: 1
        $x_1_6 = "Serial HD....:" ascii //weight: 1
        $x_1_7 = "creditForm:securityCode" wide //weight: 1
        $x_1_8 = {4d 61 71 75 69 6e 61 2e 2e 2e 2e 2e 2e 3a 20 [0-32] 55 73 75 61 72 69 6f 2e 2e 2e 2e 2e 2e 3a 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Banker_ADR_2147653526_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ADR"
        threat_id = "2147653526"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/ing/account.asp?id=" ascii //weight: 3
        $x_2_2 = "rundll32.exe shimgvw.dll,ImageView_Fullscreen C:\\" ascii //weight: 2
        $x_3_3 = "&7name=ebankDepositForm action=" ascii //weight: 3
        $x_4_4 = "Cmss 1.0 Bate" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ADT_2147653568_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ADT"
        threat_id = "2147653568"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "31A5EE7AEA6CEC538D35953869FC534283C4055DFE518FC10451F15389CA1D" ascii //weight: 1
        $x_1_2 = "3DA1C139BC255798EC78F40F6384E207679CC12FB7304FA2C0294D98EA71F27488E70D52A6C92C44A2C12FB037B4" ascii //weight: 1
        $x_1_3 = {89 82 5c 03 00 00 e8 ?? ?? ff ff 8d 45 f8 50 b9 ?? ?? 48 00 ba ?? ?? 48 00 b8 ?? ?? 48 00 e8 ?? ?? ff ff 8b 55 f8 8b 45 fc 05 38 03 00 00 e8 ?? ?? f8 ff 8b 45 fc 05 28 03 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ADY_2147653913_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ADY"
        threat_id = "2147653913"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "=======tabelafim======" ascii //weight: 1
        $x_1_2 = "=======backup======" ascii //weight: 1
        $x_1_3 = "senha 1 =" ascii //weight: 1
        $x_1_4 = "agcc_bk =" ascii //weight: 1
        $x_1_5 = "rotina=" ascii //weight: 1
        $x_1_6 = {72 61 64 65 73 63 6f 00 49 45 46 72 61 6d 65}  //weight: 1, accuracy: High
        $x_2_7 = {6d 61 71 75 69 6e 61 74 3d 00 [0-16] 68 6f 72 61 3d 00 [0-16] 64 61 64 6f 73 3d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_ADX_2147653992_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ADX"
        threat_id = "2147653992"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D965F004001F372B353EABCA0753FD5AF55C9149EC0D3CE60028D9072F39E00236A840E17FA94AFE5BF854" ascii //weight: 1
        $x_2_2 = "EA1637DE0439DF" ascii //weight: 2
        $x_1_3 = "26CE0EC1A545F539EE144C8A8BD77FDB" ascii //weight: 1
        $x_1_4 = "16D173AD59CC71B369DC78D50E4481C2C80524C5" ascii //weight: 1
        $x_1_5 = "D90231EC518AAA77AF55F02DA32AAF" ascii //weight: 1
        $x_1_6 = "85AA6A9746F116DB42E160FF1CB119B719BE" ascii //weight: 1
        $x_1_7 = "36F939E611CE75B4AA4A88C7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AEA_2147654038_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AEA"
        threat_id = "2147654038"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "castle9.com" wide //weight: 8
        $x_8_2 = "//www.batareek.net/" wide //weight: 8
        $x_4_3 = "dynamic/envio.php" wide //weight: 4
        $x_4_4 = "/envio/envio.php" wide //weight: 4
        $x_4_5 = "/itau/envio.php" wide //weight: 4
        $x_4_6 = "/send/envio.php" wide //weight: 4
        $x_4_7 = "destinatario=testeste@live.com" wide //weight: 4
        $x_4_8 = "=ykeale@hotmail.com" wide //weight: 4
        $x_4_9 = "=santa_juju_krp@hotmail.com" wide //weight: 4
        $x_4_10 = "C:\\windows\\Bank" wide //weight: 4
        $x_4_11 = "InF3cT3d" wide //weight: 4
        $x_2_12 = "=-InFo_ItA_KrP-=" wide //weight: 2
        $x_2_13 = "=InFo_Santa_KrP=" wide //weight: 2
        $x_2_14 = "titulo= ..::" wide //weight: 2
        $x_2_15 = "Token Santa-2" wide //weight: 2
        $x_2_16 = "titulo=$>>>Inf0 De$co>>>" wide //weight: 2
        $x_2_17 = "=-ItA by KaRp4 Totozim =D-=" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 5 of ($x_2_*))) or
            ((3 of ($x_4_*) and 3 of ($x_2_*))) or
            ((4 of ($x_4_*) and 1 of ($x_2_*))) or
            ((5 of ($x_4_*))) or
            ((1 of ($x_8_*) and 5 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_8_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 3 of ($x_4_*))) or
            ((2 of ($x_8_*) and 1 of ($x_2_*))) or
            ((2 of ($x_8_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AEC_2147654113_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AEC"
        threat_id = "2147654113"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 61 6e 74 23 61 6e 64 65 72 6e 23 65 74 2e 63 6f 23 6d 2e 62 23 72 2f 49 42 23 50 46 2f 4d 61 23 69 6e 2e 61 23 73 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {5f 43 6f 6d 70 72 5f 50 61 67 6d 5f 49 6d 70 5f 44 52 45 5f 00}  //weight: 1, accuracy: High
        $x_1_3 = ".si#cr#edi.co#m.b#r" ascii //weight: 1
        $x_1_4 = "?tim#eMilli#s=0&coopFill=" ascii //weight: 1
        $x_1_5 = "tmrSantaSeguraTimer" ascii //weight: 1
        $x_1_6 = "TmrReiniciaTimer" ascii //weight: 1
        $x_1_7 = "pnlItaCTbClick" ascii //weight: 1
        $x_1_8 = "lblCartao1" ascii //weight: 1
        $x_1_9 = {4d 65 6e 73 61 67 65 6d 20 64 61 20 70 e1 67 69 6e 61 20 64 61 20 77 65 62 00}  //weight: 1, accuracy: High
        $x_1_10 = {53 49 43 52 45 44 49 00 54 65 6e 74 65 20 6e 6f 76 61 6d 65 6e 74 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_Win32_Banker_AEE_2147654202_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AEE"
        threat_id = "2147654202"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "gbiehlib" wide //weight: 1
        $x_1_2 = {6d 61 69 6c 61 67 65 6e 74 [0-27] 68 65 6c 6f 6e 61 6d 65 [0-27] 75 73 65 65 68 6c 6f}  //weight: 1, accuracy: Low
        $x_1_3 = {0e 54 4b 65 79 50 72 65 73 73 45 76 65 6e 74}  //weight: 1, accuracy: High
        $x_1_4 = {56 4e 43 53 65 72 76 65 72 57 69 6e 33 32 00}  //weight: 1, accuracy: High
        $x_1_5 = "caminho" ascii //weight: 1
        $x_1_6 = "senha" ascii //weight: 1
        $x_1_7 = "computador" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AEJ_2147654342_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AEJ"
        threat_id = "2147654342"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 61 73 6b 6b 69 6c 6c 00 00 00 00 ff ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {06 00 00 00 63 6d 64 20 2f 6b 00 00 ff ff ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {13 00 00 00 2f 49 4d 20 69 65 78 70 6c 6f 72 65 2e 65 78 65 20 2f 46 00}  //weight: 1, accuracy: High
        $x_1_4 = {12 00 00 00 2f 49 4d 20 66 69 72 65 66 6f 78 2e 65 78 65 20 2f 46 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {41 75 74 6f 43 6f 6e 66 69 67 55 52 4c 00 00 00 ff ff ff ff ?? 00 00 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_6 = {0d 80 00 00 00 50 6a ec a1 ?? ?? 44 00 53 e8 ?? ?? fb ff 68 88 13 00 00 e8 ?? ?? fb ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AEL_2147654385_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AEL"
        threat_id = "2147654385"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tbsanta" wide //weight: 1
        $x_1_2 = "ragama23" wide //weight: 1
        $x_1_3 = "Provider=SQLOLEDB.1;Password=" wide //weight: 1
        $x_1_4 = "User ID=kidkid;" wide //weight: 1
        $x_1_5 = ";Data Source=184.22.136.226,1039" wide //weight: 1
        $x_1_6 = "Dados Invalidos" wide //weight: 1
        $x_1_7 = "ST_ENVIADO=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AEO_2147654513_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AEO"
        threat_id = "2147654513"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {7e 2b be 01 00 00 00 8d 45 f0 8b d7 52 8b 55 fc 8a 54 32 ff 59 2a d1 f6 d2 e8}  //weight: 4, accuracy: High
        $x_2_2 = {a4 87 7a 8b 9d 80 be}  //weight: 2, accuracy: High
        $x_2_3 = {a5 a1 a5 ae a0 b8 bd ab a6 b0 a5 9d a1 b8 cb d1 a5 a7 a4 a8 af a7 af a6 a0 a5}  //weight: 2, accuracy: High
        $x_2_4 = {80 7b 76 75 88 7d 88 85 7a}  //weight: 2, accuracy: High
        $x_1_5 = {94 9d 81 8a 7c 79 8f 7e 8b 94 a3 87 8d 7e 81 7d 81 8a 7c 94 99 87 82}  //weight: 1, accuracy: High
        $x_1_6 = {8c 81 79 7d 94 ad 7b 7e 7e 8b 82 7c 9a 8b 7e 7d 87 81 82 94 9e 7b 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AET_2147654729_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AET"
        threat_id = "2147654729"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 db 7c 65 8b 45 ?? c1 e0 ?? 03 d8 89 5d ?? 83 c7 ?? 83 ff 08 7c 48 83 ef 08 8b cf}  //weight: 1, accuracy: Low
        $x_1_2 = "Aviso Importante" ascii //weight: 1
        $x_1_3 = "Crhome.exe" ascii //weight: 1
        $x_1_4 = "fenix\\TAM\\zsantao" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AFB_2147655015_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AFB"
        threat_id = "2147655015"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6c 62 6c 42 72 6f 77 73 65 72 41 6e 65 78 61 64 6f [0-54] 62 6c 6f 71 75 65}  //weight: 10, accuracy: Low
        $x_2_2 = "blockinput" ascii //weight: 2
        $x_2_3 = "getexe" ascii //weight: 2
        $x_2_4 = "mousehook" ascii //weight: 2
        $x_1_5 = "firefox.exe" ascii //weight: 1
        $x_1_6 = "hotmail" ascii //weight: 1
        $x_1_7 = "banco" ascii //weight: 1
        $x_1_8 = ".com.br" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AFC_2147655076_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AFC"
        threat_id = "2147655076"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0e 8b 1f 39 d9 75 58 4a 74 15 8b 4e 04 8b 5f 04 39 d9 75 4b 83 c6 08 83 c7 08 4a 75 e2 eb 06 83 c6 04 83 c7 04 5a 83 e2 03 74 22 8b 0e 8b 1f 38 d9 75 41}  //weight: 1, accuracy: High
        $x_1_2 = {49 23 6e 25 73 2a 74 40 61 23 6c 23 65 25 20 2a 6f 2a 20 23 49 25 74 2a 61 40 fa 40 20 23 47 25 75 2a 61 2a 72 23 64 25 69 2a e3 40 6f 40 20 23 70 25 61 2a 72 23 61 23 20 25 74 2a 65 40 72 40 20 23 61 25 63 25 65 2a 73 23 73 25 6f 2a 2e 2a}  //weight: 1, accuracy: High
        $x_1_3 = "%n*u@R#\\%n%o*i#s%r%e*V@t@n#e%r*r*u#C%\\*s*w@o#d%n%i*W#\\%t*f*o@s#o%r*c*i#M%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AFD_2147655114_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AFD"
        threat_id = "2147655114"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0 43 66 ff 4c 24 04 75 c5}  //weight: 1, accuracy: High
        $x_1_2 = {08 45 64 5f 54 75 72 6e 6f}  //weight: 1, accuracy: High
        $x_1_3 = "WWW_GetWindowInfo" ascii //weight: 1
        $x_1_4 = "Chave de Seguran" ascii //weight: 1
        $x_1_5 = "Bradesco" ascii //weight: 1
        $x_1_6 = "Senha" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AFF_2147655133_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AFF"
        threat_id = "2147655133"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "61435E5642515C775E5D5440" ascii //weight: 20
        $x_20_2 = "7653615D4557585F" ascii //weight: 20
        $x_10_3 = "1F1D1F1F191F0A117F707B" ascii //weight: 10
        $x_10_4 = "6A11787F767572651767787211656F6510116578647E11160B10" ascii //weight: 10
        $x_5_5 = "7A5042415542425A4E117D525342" ascii //weight: 5
        $x_5_6 = "62485C505E44545217705F4758675E434542" ascii //weight: 5
        $x_5_7 = "7F5E43455F5E11705945586558434242" ascii //weight: 5
        $x_5_8 = "7C7072117174637464621F1D1F1F191F0A" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 4 of ($x_5_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_20_*) and 2 of ($x_5_*))) or
            ((2 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AFH_2147655182_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AFH"
        threat_id = "2147655182"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 00 6e 00 66 00 33 00 63 00 74 00 [0-2] 20 00 49 00 54 00}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\windows\\Bank" wide //weight: 1
        $x_1_3 = "destinatario=empresario133@hotmail.com" wide //weight: 1
        $x_1_4 = "championlover.com/envio.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Banker_AFI_2147655275_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AFI"
        threat_id = "2147655275"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "140"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "Kqz6L5T1KaLSJKb3KazJJqPKN5T9JaHFLrDSGrLIKaLEL5P5KbD9JqvSKbLE" wide //weight: 50
        $x_50_2 = "INHX+Y" wide //weight: 50
        $x_50_3 = "visitasnet.com/j1/conect.php" wide //weight: 50
        $x_20_4 = "SczqQMvXFLLGH45KHG" wide //weight: 20
        $x_20_5 = "GpfSK79lPt9XRKHXT65S" wide //weight: 20
        $x_20_6 = "IKfKCrHYDK9FOKmvH69OE4bXTaTIIsrmGp0" wide //weight: 20
        $x_20_7 = "colocando no Iexplorer" wide //weight: 20
        $x_5_8 = "0j84PbQNHl851XSc4WLczZwW" wide //weight: 5
        $x_5_9 = "GPN9pRsvkOMnfTEa" wide //weight: 5
        $x_5_10 = "GScbsONHb849XRci" wide //weight: 5
        $x_5_11 = "LRcbZR65pSm" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 4 of ($x_20_*) and 2 of ($x_5_*))) or
            ((2 of ($x_50_*) and 1 of ($x_20_*) and 4 of ($x_5_*))) or
            ((2 of ($x_50_*) and 2 of ($x_20_*))) or
            ((3 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AFJ_2147655343_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AFJ"
        threat_id = "2147655343"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "280"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Q7HqS3elBt" ascii //weight: 100
        $x_100_2 = "Kqz6L5T1KaLSJKb3KazJJqPKN5T9JaHFLrDSGrLIKaLEL5P5KbD9JqvSKbLE" ascii //weight: 100
        $x_100_3 = "vpQNHbSovrRsmkOszjBc9oBm" ascii //weight: 100
        $x_50_4 = "9fPtLfR6XbScrbBdDfT6LpBdLlR2vZRsqkOd8l" ascii //weight: 50
        $x_20_5 = "RMvjRNDkBcLuPG" ascii //weight: 20
        $x_20_6 = "IKjsCrDYH6v8T3aqIavbSabEDMfKIrTpH4jwDqbpK39CDZLBI3HYS5HQDJbJD5Ho" ascii //weight: 20
        $x_20_7 = "QMLcSc5jPG" ascii //weight: 20
        $x_20_8 = "IKLuS6nlScK" ascii //weight: 20
        $x_20_9 = "9aLjOMbiFG" ascii //weight: 20
        $x_20_10 = "9dLpPN8kS65pStTlScGz" ascii //weight: 20
        $x_20_11 = "taskkill /im mpfalert.exe /f" ascii //weight: 20
        $x_20_12 = "L7DhT79XUG" ascii //weight: 20
        $x_20_13 = "Moz9JbDKGKn1H4zT" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 9 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 7 of ($x_20_*))) or
            ((2 of ($x_100_*) and 4 of ($x_20_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((3 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AFK_2147655346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AFK"
        threat_id = "2147655346"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "140"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Kqz6L5T1KaLSJKb3KazJJqPKN5T9JaHFLrDSGrLIKaLEL5P5KbD9JqvSKbLE" ascii //weight: 100
        $x_20_2 = "J65ZOsLpSm" ascii //weight: 20
        $x_20_3 = "c:\\ProgramLog\\wsbsltfy.exe" ascii //weight: 20
        $x_20_4 = "[bb.com.br]" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AFL_2147655349_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AFL"
        threat_id = "2147655349"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "140"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Q7HqS7CwBozXOsDlTMvqSovdRszdR6KkOszjBrDbSdPfOsLCRsTfRZzpPN9sQMDbFG" ascii //weight: 100
        $x_100_2 = "JMzwQMniOIyrBZ0WA5TfRcHlTtCx85Kx84rJIKKWEIumEo1NIMvaRtTp84vK83akC3iWPMujLLCfAG" ascii //weight: 100
        $x_20_3 = "FROM ORKORK WHERE CNT = 1" wide //weight: 20
        $x_20_4 = "K65pStTa" ascii //weight: 20
        $x_20_5 = "SsbdRabk" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_20_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AGA_2147655785_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AGA"
        threat_id = "2147655785"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 10 01 00 00 c6 00 5c 8d 45 f8 03 85 e0 fe ff ff 2d 0f 01 00 00 c6 00 43 8d 45 f8 03 85 e0 fe ff ff 2d 0e 01 00 00 c6 00 41 8d 45 f8 03 85 e0 fe ff ff 2d 0d 01 00 00 c6 00 2e 8d 45 f8 03 85 e0 fe ff ff 2d 0c 01 00 00 c6 00 63 8d 45 f8 03 85 e0 fe ff ff 2d 0b 01 00 00 c6 00 65 8d 45 f8 03 85 e0 fe ff ff 2d 0a 01 00 00 c6 00 72 8d 45 f8 03 85 e0 fe ff ff 2d 09 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 00 43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e 00 45 6e 61 62 6c 65 4c 55 41}  //weight: 1, accuracy: High
        $x_1_3 = {5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 65 72 76 69 63 65 47 72 6f 75 70 4f 72 64 65 72 00 4c 69 73 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AGD_2147655881_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AGD"
        threat_id = "2147655881"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MsnTuck" ascii //weight: 2
        $x_2_2 = "signin_submit" ascii //weight: 2
        $x_2_3 = "Timer2Timer" ascii //weight: 2
        $x_2_4 = "VPrincipal" ascii //weight: 2
        $x_3_5 = "?ocid=hmlogout" ascii //weight: 3
        $x_3_6 = "edtSenhal" ascii //weight: 3
        $x_3_7 = "gaia_loginform" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AGF_2147656022_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AGF"
        threat_id = "2147656022"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 ba 02 00 00 80 8b c3 e8 ?? ?? ?? ?? 8d 55 ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 ?? 33 c9 8b c3 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "ZKLKZJBCVNBHDYUERI36786GAJSGDJGJWE" ascii //weight: 1
        $x_1_3 = "imgTelaIncialOKClick" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AGJ_2147656654_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AGJ"
        threat_id = "2147656654"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EA1EA92CEA1433968FE20127DD70DBCE57F3144A943CE609" ascii //weight: 1
        $x_1_2 = "0527C675D67ADC06210559E87B" ascii //weight: 1
        $x_1_3 = "SENHA    :" ascii //weight: 1
        $x_1_4 = "Internet Banking Empresarial" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AGK_2147656712_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AGK"
        threat_id = "2147656712"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "praquem=chaves.wab@gmail.com" ascii //weight: 5
        $x_5_2 = "http://187.109.161.164/r3.php" ascii //weight: 5
        $x_5_3 = "Captura Wab - by sysv @2012" ascii //weight: 5
        $x_1_4 = "c:\\Temp\\wab.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AGN_2147656718_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AGN"
        threat_id = "2147656718"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "c:\\windowsf\\hotmail1_" wide //weight: 5
        $x_5_2 = "http://184.82.65.108/msn/upload.php" wide //weight: 5
        $x_5_3 = "taskkill /im msnmsgr.exe /f" ascii //weight: 5
        $x_1_4 = "babaca2Timer" ascii //weight: 1
        $x_1_5 = "Servidor indisponivel, tente novamente" wide //weight: 1
        $x_1_6 = "vavino3DownloadComplete" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AGU_2147657036_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AGU"
        threat_id = "2147657036"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "160"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "Password=adm102030" ascii //weight: 50
        $x_50_2 = "ID=acessoadimistrativo" ascii //weight: 50
        $x_50_3 = "Source=mssql.acessoadimistrativo.kinghost.net,1433" ascii //weight: 50
        $x_10_4 = "delete from TAB_001_TAB" ascii //weight: 10
        $x_10_5 = "/minimized/regrum" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_50_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AGW_2147657168_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AGW"
        threat_id = "2147657168"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "INSERT INTO controle_dep_comunicacao (N_MCADDRESS , N_PORTA) VALUES (:MCADDRESS, :PORTA) " wide //weight: 1
        $x_1_2 = "netsh firewall add allowedprogram " ascii //weight: 1
        $x_1_3 = "-C -ssh -2 -P 22 -i " ascii //weight: 1
        $x_1_4 = "**Referencia Card**" ascii //weight: 1
        $x_1_5 = "HSBC BANK BRASIL S.A. - BANCO M" ascii //weight: 1
        $x_1_6 = "Banco Santander S.A." ascii //weight: 1
        $x_1_7 = "(N_USER, N_PASS) VALUES (:USER, :PASS)" ascii //weight: 1
        $x_1_8 = "http://promote.orkut.com/preview?nt=orkut.com&tt=" ascii //weight: 1
        $x_1_9 = "EmbeddedWB http://bsalsa.com/" ascii //weight: 1
        $x_1_10 = "Numero Card....:" ascii //weight: 1
        $x_1_11 = "creditForm:cardNumber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Banker_AGX_2147657185_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AGX"
        threat_id = "2147657185"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "cmd.html&cmd2=" ascii //weight: 3
        $x_3_2 = {33 43 6c 69 63 6b 13 00 [0-16] 49 6d 61 67 65}  //weight: 3, accuracy: Low
        $x_3_3 = "keybd_event" ascii //weight: 3
        $x_1_4 = "T#ent#e nov#ame#nte" ascii //weight: 1
        $x_1_5 = "Se#nha d#o Tok#en inv#" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AGY_2147657220_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AGY"
        threat_id = "2147657220"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChamadanaInternet2" ascii //weight: 1
        $x_1_2 = "BarradoExplorer2" ascii //weight: 1
        $x_1_3 = "ConfiguraesdeBloqueadordePopups2" ascii //weight: 1
        $x_1_4 = "SobreoInternetExplorer2" ascii //weight: 1
        $x_1_5 = "RelatriodePrivacidade" ascii //weight: 1
        $x_1_6 = "de Seguran" ascii //weight: 1
        $x_1_7 = "es da internet..." ascii //weight: 1
        $x_1_8 = "edtsenha" ascii //weight: 1
        $x_1_9 = "blockinput" ascii //weight: 1
        $x_1_10 = "getexe" ascii //weight: 1
        $x_1_11 = "mousehook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AHH_2147657631_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AHH"
        threat_id = "2147657631"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "320"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "txtpasswd.value=pwdeka" ascii //weight: 100
        $x_100_2 = "parent.parent.Dummy.getpwd()" ascii //weight: 100
        $x_100_3 = "<script>window.location = \"https://www.santandernet" ascii //weight: 100
        $x_10_4 = ".document.frmEnviar.txtEka.value=Eka;" ascii //weight: 10
        $x_10_5 = "Dllsaintangerc\\Release" ascii //weight: 10
        $x_10_6 = {32 30 35 2e 32 33 34 2e 31 33 34 2e 31 30 32 00 31 2e 30 2e 30 2e 30}  //weight: 10, accuracy: High
        $x_10_7 = "fMenu.AbrePagina(2773);</script>" ascii //weight: 10
        $x_10_8 = "checaAltura(){};</script" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AHJ_2147657697_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AHJ"
        threat_id = "2147657697"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "420"
        strings_accuracy = "High"
    strings:
        $x_300_1 = "C#:%\\*B#a%n%c#o*B*r*a#s*i%l#" ascii //weight: 300
        $x_100_2 = "i#n*f*e%c@t#/@inf4*/*i*n*d%e%x%.%p%h%p" ascii //weight: 100
        $x_100_3 = "%s%h#u%t#d%o%w%n* %-@f% @-#r@" ascii //weight: 100
        $x_10_4 = "/#/#c%d*x*2%0*1@5#.@t*h%a*i#e#a#s#y@d%n@s@.%c#o#m@/*m" ascii //weight: 10
        $x_10_5 = "c#m*d@ */*c% #r#m*d*i%r# */%s% @/%q%" ascii //weight: 10
        $x_10_6 = "SLwkdKzjX_5tjPF6eJypW6umSIqgMC" ascii //weight: 10
        $x_10_7 = "winkav.cpl" ascii //weight: 10
        $x_10_8 = "p*r%o#c*e#s*s*x*x#x%2%" ascii //weight: 10
        $x_10_9 = {69 6e 69 74 2e 76 72 78 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_300_*) and 1 of ($x_100_*) and 2 of ($x_10_*))) or
            ((1 of ($x_300_*) and 2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AHL_2147657803_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AHL"
        threat_id = "2147657803"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7d 03 46 eb 05 be 01 00 00 00 8b 45 ?? 33 db 8a 5c 30 ff 33 5d ?? 3b fb 7c 0a}  //weight: 2, accuracy: Low
        $x_2_2 = {2d 2d 3d 3d 53 61 6e 74 61 6e 64 65 72 3d 3d 2d 2d 00}  //weight: 2, accuracy: High
        $x_1_3 = "15B322A120B728BC2FA91143B42DAB3E96345387C502" ascii //weight: 1
        $x_1_4 = "3C4FA5F47989E60C7CFB7389EC" ascii //weight: 1
        $x_1_5 = "B9CA1BB82DAFFE65F757F86BEE62F65A4B80D4C5144A8BDD73EB7ED4C5084E5FF554F25084C112449EA32562" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AHP_2147657887_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AHP"
        threat_id = "2147657887"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "70"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "liquigas.it/immagini/informa.php" ascii //weight: 20
        $x_20_2 = "Od9XP6LpOszkPNHbRN1oPNDXBcDlRIvY" ascii //weight: 20
        $x_20_3 = "Q7HqS7CwBozYSc5aPNDZRsvbT6LjS79bSs4kOszjBc" ascii //weight: 20
        $x_20_4 = "Gd9XP6LpOsy" ascii //weight: 20
        $x_10_5 = "Kqz6L5T1KaLSJKb3KazJJqPKN5T9JaHF" ascii //weight: 10
        $x_10_6 = "N5DlPdHtON9bN4rfOt9lSszcT5n9RdHb" ascii //weight: 10
        $x_10_7 = "QMvcRt9jOIvqU7G" ascii //weight: 10
        $x_10_8 = "T7HfRMLXOsLpSsykT7Xq" ascii //weight: 10
        $x_5_9 = "QMLuS6nlScLo" ascii //weight: 5
        $x_5_10 = "LcLoSsblRW" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_20_*) and 2 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_20_*) and 3 of ($x_10_*))) or
            ((3 of ($x_20_*) and 2 of ($x_5_*))) or
            ((3 of ($x_20_*) and 1 of ($x_10_*))) or
            ((4 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AHX_2147658243_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AHX"
        threat_id = "2147658243"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5d 5b 30 2d 39 5d 7b 31 ?? 7d}  //weight: 2, accuracy: Low
        $x_2_2 = "86.55.206.170" ascii //weight: 2
        $x_2_3 = "GET /sets.txt" ascii //weight: 2
        $x_2_4 = "REGEXEND" ascii //weight: 2
        $x_2_5 = "Windows Generic File Service" wide //weight: 2
        $x_1_6 = "\\msvcr64.dll" ascii //weight: 1
        $x_1_7 = "\\dynpagefile.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AHZ_2147658290_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AHZ"
        threat_id = "2147658290"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "--=$=Inf3ct3d " wide //weight: 1
        $x_1_2 = "destinatario=" wide //weight: 1
        $x_1_3 = "titulo=>>>Inf3ct " wide //weight: 1
        $x_1_4 = "titulo=$>>>Tabela " wide //weight: 1
        $x_1_5 = "Hora..:" wide //weight: 1
        $x_1_6 = {2f 00 65 00 6e 00 76 00 69 00 6f 00 [0-2] 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Banker_VCE_2147658359_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VCE"
        threat_id = "2147658359"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "a#tua#lizac#ao.e#xe" ascii //weight: 1
        $x_1_2 = "p#a#s#s#w%d%" ascii //weight: 1
        $x_1_3 = "l*#og#in" ascii //weight: 1
        $x_1_4 = "ht#tp://lo#gin." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Banker_VCE_2147658359_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VCE"
        threat_id = "2147658359"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\win.vbs" ascii //weight: 1
        $x_1_2 = "fbProfileBrowser" ascii //weight: 1
        $x_1_3 = {85 c0 76 1e 68 01 00 11 00 6a 1b 68 00 01 00 00 68 ?? ?? ?? ?? 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {0f 8e dd 00 00 00 bb 01 00 00 00 8d 45 f4 50 b9 01 00 00 00 8b d3 8b 45 fc e8 ?? ?? ?? ff 8b 45 f4 ba ?? ?? ?? 00 e8 ?? ?? ?? ff 0f 84 aa 00 00 00 8d 45 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AIA_2147658387_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AIA"
        threat_id = "2147658387"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "230"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "q7XtsurCE7" ascii //weight: 100
        $x_50_2 = "m7mueXqZbfluvbnKmTmtfenc1cmui3ltq7ndu1mZu7mda" ascii //weight: 50
        $x_50_3 = "uZn7ncnuyWltuXrJuTndm9ns1boda3ltvgqtq9rtm9ota" ascii //weight: 50
        $x_30_4 = "xfDVDZy7mZjoB8rLx" ascii //weight: 30
        $x_30_5 = "xeDIAwvOu8nKlKDIswvOt8jQ" ascii //weight: 30
        $x_20_6 = "xhn9C2rLBtmYxgDICgTTlNn9CW" ascii //weight: 20
        $x_20_7 = "D8LUzgLY" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_30_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 2 of ($x_20_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AIF_2147658601_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AIF"
        threat_id = "2147658601"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "340"
        strings_accuracy = "High"
    strings:
        $x_200_1 = "87889E6FEC73BBB975B6400F" ascii //weight: 200
        $x_50_2 = "88869260B04AC252EE4DCA7DB241FF1A2BE020EE" ascii //weight: 50
        $x_50_3 = "33ED0AEF001BED390755D25AA877B14DD967A671B68E939190" ascii //weight: 50
        $x_30_4 = "D04AD82B1E10EF72F479AF7A8B93D872899268AB64B447D6" ascii //weight: 30
        $x_30_5 = "CEF08171FFD371C15E95EBB84B5708E66A069AC62C955A77C82" ascii //weight: 30
        $x_20_6 = "5ED8778A9B7F9C6EB1BD6DA17D80878FBB45D458A17CBE5CA87A838897" ascii //weight: 20
        $x_20_7 = "37C867BA53AE4EA277" ascii //weight: 20
        $x_20_8 = "C768B17F91956F" ascii //weight: 20
        $x_20_9 = "57FB050AE73EC7" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_200_*) and 2 of ($x_30_*) and 4 of ($x_20_*))) or
            ((1 of ($x_200_*) and 1 of ($x_50_*) and 1 of ($x_30_*) and 3 of ($x_20_*))) or
            ((1 of ($x_200_*) and 1 of ($x_50_*) and 2 of ($x_30_*) and 2 of ($x_20_*))) or
            ((1 of ($x_200_*) and 2 of ($x_50_*) and 2 of ($x_20_*))) or
            ((1 of ($x_200_*) and 2 of ($x_50_*) and 1 of ($x_30_*) and 1 of ($x_20_*))) or
            ((1 of ($x_200_*) and 2 of ($x_50_*) and 2 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AII_2147658892_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AII"
        threat_id = "2147658892"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {74 1e 8d 45 ?? 50 b9 01 00 00 00 8b d3 8b 45 ?? e8 ?? ?? ?? ?? 8b 55 ?? 8d 45 ?? e8 ?? ?? ?? ?? 43 4e 0f 85}  //weight: 3, accuracy: Low
        $x_1_2 = "Se#nha do ca#rt" ascii //weight: 1
        $x_1_3 = "o do plugin para realizar este procedimento" ascii //weight: 1
        $x_1_4 = "Inte#rn#et# @B*a#n@k@i*ng@" ascii //weight: 1
        $x_1_5 = "*/:*pt*t#h" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_VCH_2147658974_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VCH"
        threat_id = "2147658974"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C0NT4:" ascii //weight: 1
        $x_1_2 = "4G3NC1A:" ascii //weight: 1
        $x_1_3 = "4SS1N4TUR4:" ascii //weight: 1
        $x_1_4 = "banking.caixa.gov.br/SIIBC/index.processa" ascii //weight: 1
        $x_1_5 = "CURRENTVERSION\\RUN" ascii //weight: 1
        $x_1_6 = "Senha incorreta." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Banker_AIM_2147659333_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AIM"
        threat_id = "2147659333"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 61 63 72 66 66 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {03 c6 83 e7 0f 76 10 3b f0 73 10 83 ef 01 0f b7 0e 8d 74 4e 02 75 f0 3b f0 72 06 5e 5f 33 c0 5d c3}  //weight: 1, accuracy: High
        $x_1_3 = {8b 55 00 c6 04 10 00 83 c0 01 3b c7 7c f2 90 33 c9 85 ff 7e 3b 90 8a 44 24 18 0f b6 d0 02 9a ?? ?? ?? ?? 04 01 0f b6 c0 25 0f 00 00 80 79 05 48 83 c8 f0}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c4 08 85 c0 0f 84 ?? ?? ?? ?? 66 c7 00 00 00 68 ?? ?? ?? ?? 8d 44 24 10 b9 ?? ?? ?? ?? ba 01 00 00 80 e8 ?? ?? ?? ?? 83 c4 04 85 c0 0f 84 7a 01 00 00 53 8b 1d ?? ?? ?? ?? 55 68 ?? ?? ?? ?? 8d 44 24 18 50 ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AIS_2147659918_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AIS"
        threat_id = "2147659918"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 1e 8d 45 ?? 50 b9 01 00 00 00 8b d3 8b 45 ?? e8 ?? ?? ?? ?? 8b 55 ?? 8d 45 ?? e8 ?? ?? ?? ?? 43 4e 0f 85}  //weight: 5, accuracy: Low
        $x_1_2 = "senha" ascii //weight: 1
        $x_1_3 = "sa*nt*an@der.@c#o@m*" ascii //weight: 1
        $x_1_4 = "s@a*n*t#an@d*e@r#n#et*" ascii //weight: 1
        $x_1_5 = "*F@i@r*e#f" ascii //weight: 1
        $x_1_6 = "@C*a#i*x@a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AIW_2147661249_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AIW"
        threat_id = "2147661249"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/v ForceAutoLogon /d 1 /t REG_SZ /f" ascii //weight: 1
        $x_1_2 = "-C -ssh -2 -P 22 -i " ascii //weight: 1
        $x_1_3 = "Erase \"%s\"" ascii //weight: 1
        $x_1_4 = "Cadastrado" ascii //weight: 1
        $x_1_5 = "linkemail=" ascii //weight: 1
        $x_1_6 = "senha=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Banker_VCJ_2147661322_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VCJ"
        threat_id = "2147661322"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Banco Santander Brasil | Banco do juntos - Mozilla Firefox" wide //weight: 1
        $x_1_2 = "Sen Card Deb" wide //weight: 1
        $x_1_3 = "@gmail.com" wide //weight: 1
        $x_1_4 = "[espaco]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AIZ_2147661431_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AIZ"
        threat_id = "2147661431"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 8e 9b 01 00 00 bb 01 00 00 00 8d 45 f4 50 b9 01 00 00 00 8b d3 8b 45 fc e8}  //weight: 1, accuracy: High
        $x_1_2 = {68 e0 93 04 00 e8 ?? ?? ?? ff 6a 00 8d 95 ?? ?? ?? ff b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 85 ?? ?? ?? ff e8 ?? ?? ?? ff 50 e8 ?? ?? ?? ff e8 ?? ?? ?? ff eb (23|32)}  //weight: 1, accuracy: Low
        $x_1_3 = {63 6d 64 20 2f 6b 20 00 ?? ?? ?? ?? ?? ?? [0-3] 43 (23|25|2a|40) 3a (23|25|2a|40) 5c (23|25|2a|40)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AIZ_2147661431_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AIZ"
        threat_id = "2147661431"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {5c 6b 65 65 70 73 33 32 2e 65 78 65 00}  //weight: 4, accuracy: High
        $x_2_2 = {4d 34 71 75 31 6e 34 2e 00}  //weight: 2, accuracy: High
        $x_2_3 = {44 34 74 33 2e 2e 2e 2e 3a 00}  //weight: 2, accuracy: High
        $x_2_4 = {54 69 6d 65 2e 2e 2e 2e 3a 00}  //weight: 2, accuracy: High
        $x_2_5 = {4e 33 72 76 30 73 30 2e 2e 2e 2e 2e 3a 00}  //weight: 2, accuracy: High
        $x_1_6 = {44 41 54 45 2e 2e 2e 2e 3a 00}  //weight: 1, accuracy: High
        $x_1_7 = "johny-da@uol.com.br" ascii //weight: 1
        $x_1_8 = "todainfro@gmail.com" ascii //weight: 1
        $x_1_9 = "$paipai noel infor$" ascii //weight: 1
        $x_1_10 = "abrounelsantos" ascii //weight: 1
        $x_1_11 = {69 6e 66 6f 2e 6a 70 67 00}  //weight: 1, accuracy: High
        $x_1_12 = {69 6e 66 6f 2e 62 6d 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AJB_2147661509_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AJB"
        threat_id = "2147661509"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "YUQL23KL23DF90WI5E1JAS" wide //weight: 10
        $x_1_2 = "bradesco" wide //weight: 1
        $x_1_3 = "madDisAsm" ascii //weight: 1
        $x_1_4 = "MouseHookProc" ascii //weight: 1
        $x_1_5 = "screenshot" ascii //weight: 1
        $x_1_6 = "Caixa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AJE_2147663247_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AJE"
        threat_id = "2147663247"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "(\"ID_PC\", \"NMFUNCIONARIO\", \"INFORMACAO\")" wide //weight: 10
        $x_1_2 = "teclado" ascii //weight: 1
        $x_1_3 = "mensagem" wide //weight: 1
        $x_1_4 = "santander" wide //weight: 1
        $x_1_5 = "ib2.bradesco.com.br/ibpflogin" wide //weight: 1
        $x_1_6 = "Cadastro" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_ADN_2147664354_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ADN"
        threat_id = "2147664354"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 ae ca 7b c3 ff 25 ?? ?? ?? ?? 8b c0 53 33 db 6a 00 e8 ?? ?? ?? ?? 83 f8 07 75 1c 6a 01 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "Preencha corretamente os campos solicitados" ascii //weight: 1
        $x_1_3 = ".php" ascii //weight: 1
        $x_1_4 = {65 78 65 63 [0-16] 73 65 72 69 65}  //weight: 1, accuracy: Low
        $x_1_5 = {40 68 6f 74 6d 61 69 6c 2e 63 6f 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AJK_2147665886_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AJK"
        threat_id = "2147665886"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "alert(\"iToken inv" wide //weight: 1
        $x_1_2 = "MSG#Mete o Boleto Boca de Burro" ascii //weight: 1
        $x_1_3 = "bankline.itau.com.br" ascii //weight: 1
        $x_1_4 = {73 61 6e 6f 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 75 73 65 72 6e 61 6d 65 70 61 73 73 77 6f 72 64 07 69 64 73 6f 63 6b 73}  //weight: 1, accuracy: High
        $x_1_5 = "senhacartao" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AJO_2147666126_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AJO"
        threat_id = "2147666126"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zzc0KL0RzOEBwCAbO5AeuIDXmB" ascii //weight: 1
        $x_1_2 = "GDgYIzb6ToK" ascii //weight: 1
        $x_1_3 = {32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0}  //weight: 1, accuracy: High
        $x_10_4 = "GB Plugin Instalado." ascii //weight: 10
        $x_10_5 = "Maquina sem AntVirus" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AJO_2147666126_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AJO"
        threat_id = "2147666126"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "zzc0KL0RzOEBwCAbO5AeuIDXmB" ascii //weight: 1
        $x_1_2 = "GDgYIzb6ToK8crvVdBFFBMTRJ/xjlbPaYiYdsSJKO2cK9izy" ascii //weight: 1
        $x_1_3 = "GDgYIzb6ToK8hWD+pR8kcOpWrYNAemnOn+IwlXr7dXAvNMAy2++pD2w3" ascii //weight: 1
        $x_1_4 = {32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0}  //weight: 1, accuracy: High
        $x_1_5 = {8b 37 85 db 74 15 8a 02 3c 61 72 06 3c 7a 77 02 2c 20 88 06 42 46 4b}  //weight: 1, accuracy: High
        $x_1_6 = {0e 54 4b 65 79 50 72 65 73 73 45 76 65 6e 74}  //weight: 1, accuracy: High
        $x_1_7 = {35 ae ca 7b c3 ff 25 ?? ?? ?? ?? 8b c0 53 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 1c}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 0e 8b 1f 38 d9 75 ?? 4a 74 ?? 38 fd 75 ?? 4a 74 ?? 81 e3 00 00 ff 00 81 e1 00 00 ff 00 39 d9 75}  //weight: 1, accuracy: Low
        $x_1_9 = {eb 07 b2 02 e8 ?? ?? ff ff 8b 45 fc 80 78 5b 00 74 ?? 8b 45 fc 8b 40 44 80 b8 ?? ?? 00 00 01 ?? ?? 8b ?? fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Banker_AJP_2147666523_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AJP"
        threat_id = "2147666523"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {94 14 85 c9 74 0c 39 08 75 08 89 cf 8b 41 fc 4a eb 02 31 c0 8b 4c 94 14 85 c9 74 0b}  //weight: 1, accuracy: High
        $x_1_2 = {35 ae ca 7b c3 ff 25 ?? ?? ?? ?? 8b c0 53 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 1c}  //weight: 1, accuracy: Low
        $x_1_3 = {8b f0 0f b6 c3 8b 6c 87 04 eb ?? 8b 6d 00 85 ed 74 ?? 3b 75 04 75}  //weight: 1, accuracy: Low
        $x_1_4 = {eb 27 46 8b c3 34 01 84 c0 74 1b 8d 45 f4 8b 55 fc 0f b6 54 32 ff e8 ?? ?? ff ff 8b 55 f4 8d 45 f8 e8 ?? ?? ff ff 80 f3 01}  //weight: 1, accuracy: Low
        $x_1_5 = {99 f7 7d d4 8b da 3b 75 e0 7d 03 46 eb 05 be 01 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Banker_AJT_2147667479_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AJT"
        threat_id = "2147667479"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 00 6f 00 6e 00 00 00 0a 00 00 00 66 00 69 00 67 00 75 00 72 00 00 00 06 00 00 00 61 00 64 00 61 00 00 00 0c 00 00 00 52 00 65 00 6d 00 6f 00 74 00 61 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 00 6e 00 61 00 6c 00 69 00 00 00 0a 00 00 00 74 00 65 00 2e 00 63 00 6f 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {75 00 6e 00 69 00 63 00 00 00 00 00 06 00 00 00 6c 00 61 00 73 00 00 00 08 00 00 00 73 00 2e 00 63 00 6f 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {70 00 63 00 2e 00 6f 00 72 00 00 00 06 00 00 00 67 00 2e 00 62 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "/ServiceLogin?service=orku" wide //weight: 1
        $x_1_6 = "m.br/ITE/common/html/hs" wide //weight: 1
        $x_1_7 = {00 00 74 00 65 00 6d 00 33 00 32 00 5c 00 2a 00 2e 00 6f 00 63 00 61 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {5c 00 64 00 65 00 61 00 64 00 30 00 31 00 2e 00 64 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {5c 00 44 00 61 00 74 00 5c 00 41 00 5c 00 31 00 2e 00 64 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {66 00 74 00 70 00 2e 00 77 00 68 00 6c 00 30 00 30 00 36 00 34 00 2e 00 77 00 68 00 73 00 65 00 72 00 76 00 69 00 64 00 6f 00 72 00 2e 00 63 00 6f 00 6d 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {63 68 65 67 6f 6f 62 61 6e 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule TrojanSpy_Win32_Banker_AJU_2147668475_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AJU"
        threat_id = "2147668475"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TM01Timer" ascii //weight: 1
        $x_1_2 = "TMRVeficaConexao" ascii //weight: 1
        $x_1_3 = "\\logwin.ini" wide //weight: 1
        $x_10_4 = "A897BE749D" wide //weight: 10
        $x_10_5 = "85A0AF5680B096984FF11FC36996BC42E4053EE3112BDA162B23CB055182D477D564F65B86" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AKB_2147671581_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AKB"
        threat_id = "2147671581"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 41 00 56 00 41 00 53 00 54 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "datacadastro=" wide //weight: 1
        $x_1_3 = ".cpl,Mouse" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AKB_2147671581_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AKB"
        threat_id = "2147671581"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 41 00 56 00 41 00 53 00 54 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {54 41 70 70 6c 65 74 4d 6f 64 75 6c 65 31 52 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 00 74 00 60 00 75 00 61 00 62 00 16}  //weight: 1, accuracy: High
        $x_1_4 = "datacadastro=" wide //weight: 1
        $x_1_5 = {c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 42 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0}  //weight: 1, accuracy: High
        $x_1_6 = "C:\\win7xe\\uc.cpl,Mouse" wide //weight: 1
        $x_1_7 = "C:\\win7xe\\upgrade.exe" wide //weight: 1
        $x_1_8 = "C:\\win7xe\\prt.jpg" wide //weight: 1
        $x_1_9 = {43 00 3a 00 5c 00 77 00 69 00 6e 00 37 00 78 00 65 00 5c 00 77 00 69 00 6e 00 [0-12] 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Banker_AKE_2147678377_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AKE"
        threat_id = "2147678377"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b d8 3b 75 f0 7d 03 46 eb 05 be 01 00 00 00 b8 ?? ?? ?? ?? 0f b6 44 30 ff 33 c3 89 45 e4 3b 7d e4 7c 0f 8b 45 e4 05 ff 00 00 00 2b c7 89 45 e4 eb 03}  //weight: 3, accuracy: Low
        $x_3_2 = {89 45 e8 3b 75 f4 7d 03 46 eb 05 be 01 00 00 00 b8 ?? ?? ?? ?? 33 db 8a 5c 30 ff 33 5d e8 3b fb 7c 0a 81 c3 ff 00 00 00 2b df eb 02}  //weight: 3, accuracy: Low
        $x_1_3 = {89 43 04 c6 43 08 b8 8b 45 08 89 43 09 66 c7 43 0d ff e0}  //weight: 1, accuracy: High
        $x_1_4 = {07 41 72 71 75 69 76 6f 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 06 45 64 69 74 61 72 04}  //weight: 1, accuracy: Low
        $x_1_5 = {06 45 78 69 62 69 72 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 09 46 61 76 6f 72 69 74 6f 73 04}  //weight: 1, accuracy: Low
        $x_1_6 = {0b 46 65 72 72 61 6d 65 6e 74 61 73 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 05 41 6a 75 64 61 04}  //weight: 1, accuracy: Low
        $x_1_7 = {10 01 53 65 6e 64 4d 61 69 6c 5f 46 6f 72 5f 45 77 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_VCM_2147678752_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VCM"
        threat_id = "2147678752"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {e9 96 00 00 00 81 fb 02 00 00 80 75 3e 8d 55 ec b8 ?? ?? ?? 00 e8 ?? ?? ff ff 8b 55 ec 8d 45 f0 e8 ?? ?? ff ff}  //weight: 10, accuracy: Low
        $x_1_2 = {0f b6 44 38 ff 89 45 e8 47 8b 75 f8 85 f6 74 05 83 ee 04 8b 36 3b f7 7d 05}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 5c 38 ff 33 5d e4 3b 5d e8 7f 0b 81 c3 ff 00 00 00 2b 5d e8 eb 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_VCP_2147678866_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VCP"
        threat_id = "2147678866"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 11 50 83 c3 01 56 52 0f 80}  //weight: 1, accuracy: High
        $x_1_2 = {8b c8 0f bf c3 99 f7 f9 83 c2 01 0f 80 ?? 01 00 00 52 8b 55 08}  //weight: 1, accuracy: Low
        $x_1_3 = {ff d7 50 b9 50 00 00 00 ff 15 ?? ?? ?? ?? 8b 55 ?? 50 8d 4d ?? 8b 02 50 51 ff d7 8b 56 ?? 50 52 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AKI_2147678910_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AKI"
        threat_id = "2147678910"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 1e 8d 45 e0 50 b9 01 00 00 00 8b d3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 2a 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 25 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 40 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 23 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 24 00}  //weight: 1, accuracy: Low
        $x_1_2 = "\\_AsDullhillBho.pas" ascii //weight: 1
        $x_1_3 = "pnlSanta" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AKJ_2147679000_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AKJ"
        threat_id = "2147679000"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 45 d8 50 68 01 00 00 00 68 02 00 00 00 68 05 00 00 00 8d 45 ec 50 8b 04 24 8b 00 8b 00 ff 90 e0 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {a1 a1 00 52 4d 42}  //weight: 1, accuracy: High
        $x_1_3 = "pbank.95559.com.cn/netpay" ascii //weight: 1
        $x_1_4 = "/Install/Post.asp?Uid=" ascii //weight: 1
        $x_1_5 = "gpupdate /force" ascii //weight: 1
        $x_1_6 = "][Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AKO_2147679238_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AKO"
        threat_id = "2147679238"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "txtSenhaToken.value=" ascii //weight: 1
        $x_1_2 = "Time_Dentro_pega_UsuarioTimer" ascii //weight: 1
        $x_1_3 = "TIME_LE_SERVIDOR" ascii //weight: 1
        $x_1_4 = "TimePegaBotaoTimer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AKP_2147679266_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AKP"
        threat_id = "2147679266"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\oIWBQQA\\KBC7JIG\\" ascii //weight: 3
        $x_4_2 = "OI6T76T-N76kTZ:4" ascii //weight: 4
        $x_4_3 = "yRR7mT:4T7GT/ZTtQ" ascii //weight: 4
        $x_5_4 = "wIJT3AC7\\oBRCIeIJT\\1B6sI3e\\OvCC76Tp7CeBI6\\V6T7C67T4w7TTB6ke\\yvTIOI6JBkMCQ" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AKQ_2147679299_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AKQ"
        threat_id = "2147679299"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 e0 06 03 45 e8 89 45 e4 83 45 ec 06 83 7d ec 08 7c 49 83 6d ec 08 8b 4d ec 8b 45 e4 d3 e8 89 45 e8 8b 4d ec bb 01 00 00 00 d3 e3}  //weight: 2, accuracy: High
        $x_2_2 = {c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 42 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 8b c8 8b 45 f0}  //weight: 2, accuracy: High
        $x_1_3 = "(ID_PC, ERROR) Values  (:ID_PC, :ERROR)" wide //weight: 1
        $x_1_4 = ":USBLOG, DATA_COPIA = GETDATE()" wide //weight: 1
        $x_1_5 = "{2E3C3651-B19C-4DD9-A979-901EC3E930AF}" wide //weight: 1
        $x_1_6 = {2e 00 47 00 62 00 49 00 65 00 68 00 4f 00 62 00 6a 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {2e 00 47 00 62 00 50 00 6c 00 75 00 67 00 69 00 6e 00 4f 00 62 00 6a 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = "Chrome_WidgetWin_" wide //weight: 1
        $x_1_9 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 55 00 49 00 57 00 69 00 6e 00 64 00 6f 00 77 00 43 00 6c 00 61 00 73 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_2_10 = {49 00 54 00 41 00 20 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 42 00 42 00 20 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 43 00 45 00 46 00 20 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 53 00 54 00 41 00 20 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AKR_2147679528_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AKR"
        threat_id = "2147679528"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 0f bf c3 99 f7 f9 83 c2 01 0f 80 ?? 01 00 00 52 8b 55 08}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d7 50 b9 50 00 00 00 ff 15 ?? ?? ?? ?? 8b 55 ?? 50 8d 4d ?? 8b 02 50 51 ff d7 8b 56 ?? 50 52 e8}  //weight: 1, accuracy: Low
        $x_1_3 = "CodigoSTR" ascii //weight: 1
        $x_1_4 = "Consulta e Altera" wide //weight: 1
        $x_1_5 = "javascript:acessaPagina" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Banker_AKW_2147680281_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AKW"
        threat_id = "2147680281"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b da 3b 75 ec 7d 03 46 eb 05 be 01 00 00 00 8b 45 f0 0f b7 44 70 fe 33 d8 8d 45 cc 50 89 5d d0}  //weight: 10, accuracy: High
        $x_10_2 = {0f b7 44 70 fe 33 c3 89 45 e4 3b 7d e4 7c 0f 8b 45 e4 05 ff 00 00 00 2b c7 89 45 e4 eb 03 29 7d e4}  //weight: 10, accuracy: High
        $x_10_3 = {83 e8 04 8b 00 8b d8 85 db 7e 32 be 01 00 00 00 8d 45 e8 8b 15 ?? ?? ?? ?? 0f b7 54 7a fe 8b 4d fc 0f b7 4c 71 fe 66 33 d1}  //weight: 10, accuracy: Low
        $x_1_4 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 64 00 6f 00 53 00 75 00 62 00 6d 00 69 00 74 00 28 00 29 00 3b 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 00 57 00 57 00 5f 00 47 00 65 00 74 00 57 00 69 00 6e 00 64 00 6f 00 77 00 49 00 6e 00 66 00 6f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 30 00 78 00 46 00 46 00 46 00 46 00 46 00 46 00 46 00 46 00}  //weight: 1, accuracy: Low
        $x_1_6 = "macrodirect.com.ar/" ascii //weight: 1
        $x_1_7 = "/RetailHomeBankingWeb/access.do" ascii //weight: 1
        $x_1_8 = "/RetailInstitucionalWeb/home.do" ascii //weight: 1
        $x_1_9 = "Supervielle Banco" ascii //weight: 1
        $x_1_10 = "Banco Credicoop Coop. Ltdo." ascii //weight: 1
        $x_1_11 = "Banco Galicia - Personas" ascii //weight: 1
        $x_1_12 = {42 42 56 41 20 46 72 61 6e 63 c3 a9 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_ALA_2147682194_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ALA"
        threat_id = "2147682194"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {66 83 eb 03 66 ff 45 f6 66 83 fb 01 77 b1 8d 45 e4 50 0f b7 d3 b9 03 00 00 00 8b 45 fc ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b f8 66 2b 7d f8 0f b7 45 f6 66 03 45 fa 66 2b f8 8d 45 e0 8b d7}  //weight: 3, accuracy: Low
        $x_1_2 = {74 00 70 00 70 00 2e 00 64 00 61 00 74 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 73 00 63 00 62 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 00 2f 00 69 00 6e 00 66 00 65 00 2f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 6d 00 73 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 00 2f 00 69 00 6e 00 66 00 6f 00 2f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 55 00 53 00 52 00}  //weight: 1, accuracy: Low
        $x_1_5 = {3f 00 74 00 69 00 70 00 6f 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 00 6e 00 6f 00 6d 00 65 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_6 = {53 00 45 00 4d 00 41 00 2e 00 53 00 43 00 42 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 53 00 45 00 4d 00 41 00 32 00 2e 00 53 00 43 00 42 00}  //weight: 1, accuracy: Low
        $x_1_7 = {33 d2 b8 1c 00 00 00 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8d 4d ?? 33 d2 b8 26 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_8 = {74 00 70 00 70 00 2e 00 64 00 61 00 74 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_9 = {2e 00 2f 00 69 00 6e 00 66 00 65 00 2f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3f 00 74 00 69 00 70 00 6f 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_10 = {26 00 6e 00 6f 00 6d 00 65 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 00 64 00 61 00 64 00 6f 00 73 00 3d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_ALB_2147682296_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ALB"
        threat_id = "2147682296"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mas\\GbPlugin\\cef.gpc" wide //weight: 1
        $x_1_2 = "/saveinfectcx.php?idcli=" wide //weight: 1
        $x_1_3 = "ins\\infgat" wide //weight: 1
        $x_1_4 = "&gbCX=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ALF_2147682523_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ALF"
        threat_id = "2147682523"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "152"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00 00}  //weight: 100, accuracy: High
        $x_1_2 = {26 67 62 47 46 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {26 00 67 00 62 00 47 00 46 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "http://ilovepromote.com/" wide //weight: 1
        $x_1_5 = {2f 69 6c 6f 76 65 70 72 [0-15] 6f 6d 6f 74 65 2e 63 6f 6d 2f}  //weight: 1, accuracy: Low
        $x_50_6 = {63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 [0-8] 2e 00 6e 00 65 00 74 00 00}  //weight: 50, accuracy: Low
        $x_50_7 = {63 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 50 72 6f 67 72 61 6d 61 73 20 28 78 38 36 29 5c 47 62 50 6c 75 67 69 6e 5c 62 62 2e 67 70 63 00 00}  //weight: 50, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_ALG_2147682891_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ALG"
        threat_id = "2147682891"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 4e 47 28 53 45 52 56 45 52 54 4f 50 49 4e 47 29 20 74 68 65 6e 06 1f 66 6c 61 67 20 3d 20 76 72 66 28 70 68 70 62 69 74 20 26 20 22 3f 61 3d 63 68 65 63 6b 22 29 06 10 69 66 20 66 6c 61 67 20 3d 20 31 20 74 68 65 6e 06 0b 6a 61 63 68 65 63 6b 20 3d 20 31 06 7f 46 46 20 3d 20 41 50 59 59 20 26 20 50 50 28 2d 32 37 39 2b 31 30 35 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ALI_2147682941_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ALI"
        threat_id = "2147682941"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a 03 0f b6 80 ?? ?? ?? ?? 33 d2 8a 53 01 0f b6 92 ?? ?? ?? ?? c1 e2 06 03 c2 33 d2 8a 53 02 0f b6 92 ?? ?? ?? ?? c1 e2 0c 03 c2 33 d2 8a 53 03}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58}  //weight: 1, accuracy: High
        $x_1_3 = "oPLvqgGPCojdlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ALN_2147683439_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ALN"
        threat_id = "2147683439"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "YUQL23KL23DF90WI5E1JAS467NMCXXL" wide //weight: 1
        $x_1_2 = {41 00 56 00 47 00 [0-22] 00 5c 00 41 00 56 00 41 00 53 00 54}  //weight: 1, accuracy: Low
        $x_1_3 = "winmgmts:\\\\localhost\\root\\cimv2" wide //weight: 1
        $x_1_4 = {84 c0 74 0d 8b 45 f8 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 45 ec e8 ?? ?? ?? ?? 8d 45 ec 50 8d 4d e8 ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 e8 58 e8 ?? ?? ?? ?? 8b 45 ec e8 ?? ?? ?? ?? 84 c0 74 10 8b 45 f8 ba}  //weight: 1, accuracy: Low
        $x_1_5 = {84 c0 74 0d 8b 45 f8 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 45 f0 e8 ?? ?? ?? ?? 8d 45 f0 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f0 e8 ?? ?? ?? ?? 84 c0 74 10 8b 45 f8 ba}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Banker_ALP_2147683600_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ALP"
        threat_id = "2147683600"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 42 75 73 63 61 44 61 64 6f 73 12 00}  //weight: 1, accuracy: High
        $x_1_2 = "B2747BF3741A7CC1750A6C4C33DB5324DB2C7CE135A8BDB245D96D41F5EA7E22E54ABC63BB" ascii //weight: 1
        $x_1_3 = "115S4DS5DF4S6" ascii //weight: 1
        $x_1_4 = {a1 78 5b 45 00 50 8d 45 d8 50 b9 ?? ?? 45 00 ba ?? ?? 45 00 8b 45 fc 8b 18 ff 13 8b 55 d8 b8 78 5b 45 00 e8 ?? ?? fb ff 83 3d 78 5b 45 00 00 74 25 8d 55 d0 a1 78 5b 45 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ALQ_2147684139_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ALQ"
        threat_id = "2147684139"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "brt.fuck\\Novo\\brt$fck" wide //weight: 1
        $x_1_2 = "tmReconectaTimer" ascii //weight: 1
        $x_1_3 = "CasaFake" ascii //weight: 1
        $x_1_4 = "TfEspelho" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Banker_ALS_2147684174_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ALS"
        threat_id = "2147684174"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 44 70 fe 33 c3 89 45 e4 3b 7d e4 7c 0f 8b 45 e4 05 ff 00 00 00 2b c7 89 45 e4 eb 03}  //weight: 1, accuracy: High
        $x_1_2 = "FeatureControl\\FEATURE_ENABLE_SCRIPT_PASTE_" wide //weight: 1
        $x_1_3 = {5c 00 50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 45 00 58 00 54 00 5c 00 43 00 4c 00 53 00 49 00 44 00 5c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\_MyBHO\\uPrinc\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ALT_2147684487_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ALT"
        threat_id = "2147684487"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "JGk21gG" ascii //weight: 2
        $x_2_2 = "UpdaterLogTeck" ascii //weight: 2
        $x_1_3 = "HJI8.zip" ascii //weight: 1
        $x_1_4 = "I6H8.exe" ascii //weight: 1
        $x_2_5 = {35 ae ca 7b c3 ff 25 ?? ?? ?? ?? 8b c0 53 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 1c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AMB_2147685224_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AMB"
        threat_id = "2147685224"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 1b 8a 4c 0b ff 0f b7 5d f0 c1 eb 08 32 cb 88 4c 10 ff 0f b7 45 f2 8b 55 fc 0f b6 44 02 ff 66 03 45 f0 66 69 c0 6d ce 66 05 bf 58}  //weight: 2, accuracy: High
        $x_1_2 = "(ID_PC, USBLOG) Values (:ID_PC, :USBLOG)" wide //weight: 1
        $x_1_3 = "RE-COPIADO PARA" wide //weight: 1
        $x_1_4 = "Chrome_WidgetWin_" wide //weight: 1
        $x_1_5 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 55 00 49 00 57 00 69 00 6e 00 64 00 6f 00 77 00 43 00 6c 00 61 00 73 00 73 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AMQ_2147686981_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AMQ"
        threat_id = "2147686981"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 73 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {61 6d 69 64 61 6c 61 73 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_2_3 = {61 74 6d 31 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_1_4 = {44 69 73 70 6f 73 69 74 69 76 6f 20 64 65 20 c1 75 64 69 6f 20 64 6f 20 57 69 6e 64 6f 77 73}  //weight: 1, accuracy: High
        $x_1_5 = {42 63 4c 75 50 47 00}  //weight: 1, accuracy: High
        $x_1_6 = {4d 72 50 31 4b 61 62 31 4c 61 4c 39 4b 71 7a 42 4e 47 00}  //weight: 1, accuracy: High
        $x_1_7 = {31 d2 f7 f1 4e 80 c2 30 80 fa 3a 72 03 80 c2 07 88 16 09 c0 75 ea 59 5a 29 f1 29 ca 76 10 01 d1 b0 30 29 d6 eb 03 88 04 32 4a 75 fa 88 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_AMS_2147687502_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AMS"
        threat_id = "2147687502"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 00 42 00 53 00 45 00 4e 00 48 00 41 00 36 00 7c 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 00 53 00 42 00 43 00 54 00 4f 00 4b 00 45 00 4e 00 7c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {42 00 42 00 4a 00 53 00 43 00 4f 00 4e 00 54 00 41 00 7c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 00 45 00 46 00 53 00 45 00 4e 00 48 00 41 00 36 00 7c 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "escolagarbi.com" wide //weight: 1
        $x_1_6 = {2f 63 6f 6e 74 2f [0-30] 2f 61 63 65 73 73 6f 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ANE_2147689806_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ANE"
        threat_id = "2147689806"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/ctd/noti.php" ascii //weight: 2
        $x_2_2 = "whitehouse.exe" ascii //weight: 2
        $x_2_3 = "@uol.com.br" ascii //weight: 2
        $x_2_4 = "bradesco.recadastramento@gmail.com" ascii //weight: 2
        $x_2_5 = "ritamariasantos2014@gmail.com" ascii //weight: 2
        $x_2_6 = "4VISO:4S F3R145 4C4B0U!" ascii //weight: 2
        $x_2_7 = "utildrogaria19" ascii //weight: 2
        $x_2_8 = "N-O-M-E__________PC.:" ascii //weight: 2
        $x_2_9 = "N*O*M*E*-------->PC.:" ascii //weight: 2
        $x_2_10 = "S-E-R-I-A-L______HD.:" ascii //weight: 2
        $x_2_11 = "S*E*R*I*A*L*---->HD.:" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Banker_ANF_2147689878_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ANF"
        threat_id = "2147689878"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UHJvdmlkZXI9U1FMT0xFREIuMTtQYXNzd29yZD1yMnIzM2Nwb" ascii //weight: 1
        $x_1_2 = {55 30 56 4f 53 45 45 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 55 31 42 55 43 42 51 59 58 4e 7a 64 32 39 79 5a 44 6f 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {63 32 46 6c 65 48 42 6c 63 6d 6c 68 62 69 35 6a 62 77 3d 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {45 72 72 6f 3a 20 4c 4f 47 49 4e 3a 20 00}  //weight: 1, accuracy: High
        $x_1_6 = {5b 49 4e 49 43 49 4f 5d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ANL_2147691749_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ANL"
        threat_id = "2147691749"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AMERICANAS" ascii //weight: 1
        $x_1_2 = "Operadora.:" ascii //weight: 1
        $x_1_3 = "Usuario...:" ascii //weight: 1
        $x_1_4 = "Senha.....:" ascii //weight: 1
        $x_1_5 = "Nome Cartao....:" ascii //weight: 1
        $x_1_6 = "Numero Card....:" ascii //weight: 1
        $x_1_7 = "Validade.......:" ascii //weight: 1
        $x_1_8 = "SOFTWARE\\Borland\\Delphi\\" ascii //weight: 1
        $x_1_9 = {8b 0e 8b 1f 38 d9 75 41 4a 74 17 38 fd 75 3a 4a 74 10 81 e3 00 00 ff 00 81 e1 00 00 ff 00 39 d9 75 27}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ANM_2147691750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ANM"
        threat_id = "2147691750"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "'00110 10001 01001 11000 00101 10100 01100 00011 10010 01010'" ascii //weight: 1
        $x_1_2 = "'COD_BARNOSSO';var a=document.getElementsByTagName('img')" ascii //weight: 1
        $x_1_3 = "Mozilla/3.0 (compatible; Indy Library)" ascii //weight: 1
        $x_1_4 = {c1 e0 06 03 d8 89 ?? ?? 83 c7 06 83 ff 08 7c ?? 83 ef 08 8b cf 8b ?? ?? d3 eb 8b cf b8 01 00 00 00 d3 e0 8b c8 8b ?? ?? 99 f7 f9}  //weight: 1, accuracy: Low
        $x_1_5 = {73 61 6e 6f 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 75 73 65 72 6e 61 6d 65 70 61 73 73 77 6f 72 64 07 69 64 73 6f 63 6b 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ANO_2147691751_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ANO"
        threat_id = "2147691751"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "o, Por favor digite novamente." ascii //weight: 1
        $x_1_2 = "Browser Anexado:" ascii //weight: 1
        $x_1_3 = "B.A.N.K.-.H.S.B.C" ascii //weight: 1
        $x_1_4 = "ERRO: Acrobat Readers com defeito, contacte seu revendedor." ascii //weight: 1
        $x_1_5 = {8b 4b 70 ba ?? ?? ?? ?? 8b c6 e8 ee d3 ff ff dd 43 40 d8 1d ?? ?? ?? ?? df e0 9e 76 1f ff 73 44 ff 73 40 8d 55 f8 33 c0 e8 00 62 ff ff 8b 4d f8 ba ?? ?? ?? ?? 8b c6 e8 c1 d3 ff ff 8b 7b 20 85 ff 75 0a 83 7b 1c 00 0f 84 88 00 00 00 83 7b 1c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ANQ_2147691774_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ANQ"
        threat_id = "2147691774"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 6c 74 3d 22 49 6e 66 6f 72 6d 65 20 73 75 61 20 73 65 6e 68 61 20 64 65 20 36 20 64 c3 ad 67 69 74 6f 73 2e 22}  //weight: 1, accuracy: High
        $x_1_2 = "Sname=tokenDuploClique> <INPUT type=hidden name=codigoTransacao>" ascii //weight: 1
        $x_1_3 = "=type=\"password\" class=\"campo\" size=\"6\" maxlength=\"6\" />&nbsp;" ascii //weight: 1
        $x_1_4 = "Essa valida&#231;&#227;o valer&#225; para as demais opera&#231" ascii //weight: 1
        $x_1_5 = "javascript:acessaPagina(\"seleciona_investimento.processa\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ANS_2147692048_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ANS"
        threat_id = "2147692048"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CA7EAA70A467F25CB968B9769E7195DC470533" wide //weight: 1
        $x_1_2 = "C57E9861BF5FB1B88C878C9277AF" wide //weight: 1
        $x_1_3 = "FD38D224FA14F53E291CF00A180D09E8" wide //weight: 1
        $x_1_4 = "FD1EF131ED22F248DA20F0" wide //weight: 1
        $x_1_5 = "<|gets|>" wide //weight: 1
        $x_1_6 = "<|SocketMain|>" wide //weight: 1
        $x_1_7 = "<|REQUESTKEYBOARD|>" wide //weight: 1
        $x_1_8 = "<|SENDINFO|>" wide //weight: 1
        $x_1_9 = "<|reini|>" wide //weight: 1
        $x_1_10 = "<|dekl|>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_Win32_Banker_ANS_2147692048_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ANS"
        threat_id = "2147692048"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JavaTimer" ascii //weight: 1
        $x_1_2 = "427261646573636F20532F41" ascii //weight: 1
        $x_1_3 = "53616E74616E646572" ascii //weight: 1
        $x_1_4 = "|NOSenha|" ascii //weight: 1
        $x_1_5 = "|REQUESTKEYBOARD|" ascii //weight: 1
        $x_1_6 = "PanelSicrTkn" ascii //weight: 1
        $x_1_7 = "{SENHA6IT}" ascii //weight: 1
        $x_1_8 = "{TOKENUNI}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_Win32_Banker_ANS_2147692048_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ANS"
        threat_id = "2147692048"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "53616E74616E646572" wide //weight: 1
        $x_1_2 = "43616978612045636F6EF46D696361204665646572616C" wide //weight: 1
        $x_1_3 = "427261646573636F20532F41" wide //weight: 1
        $x_1_4 = "4349544942414E4B" wide //weight: 1
        $x_1_5 = "42616E636F20497461FA" wide //weight: 1
        $x_1_6 = "696578706C6F72652E657865" wide //weight: 1
        $x_1_7 = "66697265666F782E657865" wide //weight: 1
        $x_1_8 = "6368726F6D652E657865" wide //weight: 1
        $x_1_9 = "6A6176612E657865" wide //weight: 1
        $x_1_10 = "6A617661772E657865" wide //weight: 1
        $x_1_11 = "PanelCITI" ascii //weight: 1
        $x_1_12 = "PanelHSBC" ascii //weight: 1
        $x_1_13 = "PanelSICOOB" ascii //weight: 1
        $x_1_14 = "PanelSICRASS" ascii //weight: 1
        $x_1_15 = "PanelSANTA" ascii //weight: 1
        $x_1_16 = "PanelITAU" ascii //weight: 1
        $x_1_17 = "|REQUESTKEYBOARD|" wide //weight: 1
        $x_1_18 = "|SENDINFO|" wide //weight: 1
        $x_1_19 = "|REQUESTINFO|" wide //weight: 1
        $x_1_20 = "|NOSenha|" wide //weight: 1
        $x_1_21 = "|SenhaO|" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Banker_ANS_2147692048_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ANS"
        threat_id = "2147692048"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Nascimento corretamente" wide //weight: 1
        $x_1_2 = "SMS corretamente" wide //weight: 1
        $x_1_3 = "Certificado corretamente" wide //weight: 1
        $x_1_4 = "Acesso corretamente" wide //weight: 1
        $x_1_5 = "a sua Tabela corretamente" wide //weight: 1
        $x_1_6 = "O dispositivo foi atualizado com sucesso e seu acesso" wide //weight: 1
        $x_1_7 = "Token corretamente" wide //weight: 1
        $x_1_8 = "Senha corretamente" wide //weight: 1
        $x_1_9 = "caracteres da imagem corretamente" wide //weight: 1
        $x_1_10 = "P-ATIVADO" wide //weight: 1
        $x_1_11 = "P-DESATIVADO" wide //weight: 1
        $x_1_12 = "|REQUESTKEYBOARD|" wide //weight: 1
        $x_1_13 = "|MousePos|" wide //weight: 1
        $x_1_14 = "|SENDINFO|" wide //weight: 1
        $x_1_15 = "|Ajusta|" wide //weight: 1
        $x_1_16 = "|NOSenha|" wide //weight: 1
        $x_1_17 = "|SocketMain|" wide //weight: 1
        $x_1_18 = "SendCMD" ascii //weight: 1
        $x_1_19 = "JavaTimer" ascii //weight: 1
        $x_1_20 = "SicoobTimer" ascii //weight: 1
        $x_1_21 = "ITAUEmpresaTimer" ascii //weight: 1
        $x_1_22 = "SANTAEmpresaTimer" ascii //weight: 1
        $x_1_23 = "BBEstiloTimer" ascii //weight: 1
        $x_1_24 = "SICREDITimer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule TrojanSpy_Win32_Banker_ANS_2147692048_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ANS"
        threat_id = "2147692048"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Nascimento corretamente" wide //weight: 1
        $x_1_2 = "SMS corretamente" wide //weight: 1
        $x_1_3 = "Certificado corretamente" wide //weight: 1
        $x_1_4 = "Acesso corretamente" wide //weight: 1
        $x_1_5 = "a sua Tabela corretamente" wide //weight: 1
        $x_1_6 = "O dispositivo foi atualizado com sucesso e seu acesso" wide //weight: 1
        $x_1_7 = "Token corretamente" wide //weight: 1
        $x_1_8 = "em andamento!" wide //weight: 1
        $x_1_9 = "redirecionar o acesso?" wide //weight: 1
        $x_1_10 = "P-ATIVADO" wide //weight: 1
        $x_1_11 = "P-DESATIVADO" wide //weight: 1
        $x_1_12 = "|REQUESTKEYBOARD|" wide //weight: 1
        $x_1_13 = "|MousePos|" wide //weight: 1
        $x_1_14 = "|DadosCliente|" wide //weight: 1
        $x_1_15 = "|Extensions|" wide //weight: 1
        $x_1_16 = "|BugWindows|" wide //weight: 1
        $x_1_17 = "|AbrirNovaAba|" wide //weight: 1
        $x_1_18 = "|SENDINFO|" wide //weight: 1
        $x_1_19 = "EvDataAvailable" wide //weight: 1
        $x_1_20 = "SendCMD" wide //weight: 1
        $x_1_21 = "BlockedBank" wide //weight: 1
        $x_1_22 = "tmDisconnectTimer" wide //weight: 1
        $x_1_23 = "tmStopFakeTimer" wide //weight: 1
        $x_1_24 = "JavaTimer" wide //weight: 1
        $x_1_25 = "Tform_padrao_funcionais8" wide //weight: 1
        $x_1_26 = "facryth" wide //weight: 1
        $x_1_27 = "BT_GOTABELUDAClick" wide //weight: 1
        $x_1_28 = "Tform_padrao_BLUKADAS8" wide //weight: 1
        $x_1_29 = "BT_ENVSENClickN" wide //weight: 1
        $x_1_30 = "tmReconectaTimer" wide //weight: 1
        $x_1_31 = "FORCETimer" wide //weight: 1
        $x_1_32 = "CINFConnected" wide //weight: 1
        $x_1_33 = "tmDesligaITimer" wide //weight: 1
        $x_1_34 = "tmParaFTimer" wide //weight: 1
        $x_1_35 = "TZDecompressionStream" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Banker_ANY_2147692847_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ANY"
        threat_id = "2147692847"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=\"E&xcluir arquivos originais\"" ascii //weight: 1
        $x_1_2 = "=\"&Tipos de arquivo\"" ascii //weight: 1
        $x_1_3 = "=\"Homepage da Layout do Brasil\"" ascii //weight: 1
        $x_1_4 = {63 25 25 77 69 6e 64 6f 77 73 25 73 79 73 74 65 6d 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 5c 73 6d 73 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ANZ_2147692873_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ANZ"
        threat_id = "2147692873"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 79 6d 61 6e 74 65 63 20 4e 65 74 44 72 69 76 65 72 20 4d 6f 6e 69 74 6f 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 63 41 66 65 65 2e 49 6e 73 74 61 6e 74 55 70 64 61 74 65 2e 4d 6f 6e 69 74 6f 72 00}  //weight: 1, accuracy: High
        $x_1_3 = ".gov.br/" ascii //weight: 1
        $x_1_4 = "** WriteProcessMemory failed write_addr=%x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ANX_2147693364_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ANX"
        threat_id = "2147693364"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cartao de Credito :" wide //weight: 1
        $x_1_2 = "Cod. de Seg.  Card:" wide //weight: 1
        $x_1_3 = "Senha de Seis:" wide //weight: 1
        $x_1_4 = "Informa: Um ou mais dados est" wide //weight: 1
        $x_1_5 = "BRADA CASHER:" wide //weight: 1
        $x_1_6 = "SENHA CARTAO:" wide //weight: 1
        $x_1_7 = "PASSWORD ITA :" wide //weight: 1
        $x_1_8 = "SANTANDER INFORMA!:" wide //weight: 1
        $x_1_9 = "CVV.:" wide //weight: 1
        $x_1_10 = "CPF.:" wide //weight: 1
        $x_1_11 = "SysLoader\\install.txt" wide //weight: 1
        $x_1_12 = "internetbankingcaixa" wide //weight: 1
        $x_1_13 = "BB INFORMA : Digite" wide //weight: 1
        $x_1_14 = "Hsbc Informa: Digite" wide //weight: 1
        $x_1_15 = "TskManager" wide //weight: 1
        $x_1_16 = "senderedemail.tmp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule TrojanSpy_Win32_Banker_ANX_2147693364_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ANX"
        threat_id = "2147693364"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Informa: Um ou mais dados est" wide //weight: 1
        $x_1_2 = {43 00 56 00 56 00 [0-1] 3a 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 00 50 00 46 00 [0-1] 3a 00}  //weight: 1, accuracy: Low
        $x_1_4 = "DATA NASC." wide //weight: 1
        $x_1_5 = "\\INF.txt" wide //weight: 1
        $x_1_6 = "SENHA_CARD:" wide //weight: 1
        $x_1_7 = "o de recadastramento realizada com sucesso!." wide //weight: 1
        $x_1_8 = "Senha Bank Fone BB incorreta!" wide //weight: 1
        $x_1_9 = "Senha Internet Banking:" wide //weight: 1
        $x_1_10 = "Sua senha deve ter mais de 6 caracteres" wide //weight: 1
        $x_1_11 = "lidos, por favor, tente novamente." wide //weight: 1
        $x_1_12 = "Data de Nascimento Invalida!" wide //weight: 1
        $x_1_13 = "de CPF Invalido!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule TrojanSpy_Win32_Banker_AOA_2147694320_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOA"
        threat_id = "2147694320"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\GbPlugin" ascii //weight: 1
        $x_1_2 = "\\Scpad" ascii //weight: 1
        $x_1_3 = "Bradinha" ascii //weight: 1
        $x_1_4 = "Laranja" ascii //weight: 1
        $x_1_5 = {ba 04 00 00 00 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 55 d0 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 d0 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 55 cc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 cc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 55 c8 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 c8 8b c6 e8 ?? ?? ?? ?? 0f b6 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AOE_2147695564_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOE"
        threat_id = "2147695564"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".postfixcombo.com" ascii //weight: 1
        $x_1_2 = "95966D8E9266A9BB8AD567C687CA8E" ascii //weight: 1
        $x_1_3 = "36FE0D1CF1051A29EF060A" ascii //weight: 1
        $x_1_4 = "1CE233C2916DB848" ascii //weight: 1
        $x_1_5 = {eb 05 bf 01 00 00 00 8b 45 e4 33 db 8a 5c 38 ff 33 5d e0 3b 5d ec 7f 0b 81 c3 ff 00 00 00 2b 5d ec eb 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Banker_AOH_2147696659_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOH"
        threat_id = "2147696659"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 75 00 73 00 65 00 72 00 2e 00 71 00 7a 00 6f 00 6e 00 65 00 2e 00 71 00 71 00 2e 00 63 00 6f 00 6d 00 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (30|2d|39|00) (30|2d|39|00)}  //weight: 10, accuracy: Low
        $x_3_2 = "select * from urls order by last_visit_time DESC limit 0,10;" ascii //weight: 3
        $x_3_3 = "count/i/addInstall.action?params={\"systemtype:" ascii //weight: 3
        $x_2_4 = {00 00 49 00 6e 00 69 00 74 00 65 00 63 00 68 00 53 00 48 00 54 00 54 00 50 00 54 00 72 00 61 00 79 00 41 00 67 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_5 = {00 00 6e 00 6f 00 73 00 73 00 76 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_1_6 = {00 00 6b 00 62 00 73 00 74 00 61 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 00 6b 00 66 00 63 00 63 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 00 77 00 6f 00 6f 00 72 00 69 00 62 00 61 00 6e 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 00 73 00 68 00 69 00 6e 00 68 00 61 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 00 6b 00 6e 00 62 00 61 00 6e 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 00 6e 00 6f 00 6e 00 67 00 68 00 79 00 75 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 00 62 00 75 00 73 00 61 00 6e 00 62 00 61 00 6e 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_13 = {00 00 68 00 61 00 6e 00 61 00 62 00 61 00 6e 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_14 = {00 00 6a 00 62 00 62 00 61 00 6e 00 6b 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_VCV_2147696690_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VCV"
        threat_id = "2147696690"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CODIGOTK:......: " wide //weight: 1
        $x_1_2 = "nairepxE asareS" wide //weight: 1
        $x_1_3 = "osseca o odnaicini ,edraugA" wide //weight: 1
        $x_1_4 = "ocnab mu euq siam edep adiv A" wide //weight: 1
        $x_1_5 = "kcalB draCretsaM" wide //weight: 1
        $x_1_6 = "Citibank" wide //weight: 1
        $x_1_7 = "063 oviV" wide //weight: 1
        $x_1_8 = ".www//:ptth" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_Win32_Banker_AOI_2147696778_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOI"
        threat_id = "2147696778"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 61 6e 63 6f 42 72 61 73 69 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 5c 72 75 6e 64 6c 6c 33 32 7e 2e 68 6c 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 5c 6c 6f 67 70 61 73 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 65 72 76 69 64 6f 72 20 53 4d 54 50 00}  //weight: 1, accuracy: High
        $x_1_5 = {41 73 73 75 6e 74 6f 20 64 6f 20 45 6d 61 69 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 6f 6f 72 64 65 6e 61 64 61 20 41 63 65 69 74 61 20 54 6f 74 61 6c 6d 65 6e 74 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {46 69 6e 61 6c 69 7a 61 6e 64 6f 2e 2e 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Banker_AOJ_2147696833_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOJ"
        threat_id = "2147696833"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {70 00 68 00 70 00 2e 00 ?? 61 00 74 00 6c 00 75 00 73 00 6e 00 6f 00 63 00 2f 00 72 00 62 00 2e 00 6d 00 6f 00 63 00 2e 00 [0-16] 2e 00 77 00 77 00 77 00}  //weight: 4, accuracy: Low
        $x_4_2 = {70 68 70 2e ?? 61 74 6c 75 73 6e 6f 63 2f 72 62 2e 6d 6f 63 2e [0-16] 2e 77 77 77}  //weight: 4, accuracy: Low
        $x_1_3 = "Novo acesso Connect Bank." ascii //weight: 1
        $x_1_4 = "Novo acesso Hsbc bank-line..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_VCW_2147696927_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VCW"
        threat_id = "2147696927"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 50 6c 41 70 70 6c 65 74 00 46 6f 78 69 74 52 65 61 64 65 72 2e 63 70 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {54 00 41 00 50 00 50 00 41 00 44 00 4d 00 49 00 4e 00 49 00 53 00 54 00 52 00 41 00 44 00 4f 00 52 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AOK_2147697013_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOK"
        threat_id = "2147697013"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 04 8b 00 89 ?? ?? 33 f6 bf 00 01 00 00 66 83 eb 43 74 ?? 66 ff cb 0f}  //weight: 1, accuracy: Low
        $x_1_2 = "Bank of America log-in" wide //weight: 1
        $x_1_3 = "Chrome_WidgetWin_1" wide //weight: 1
        $x_1_4 = "MOZILLAUIWINDOWCLASS" wide //weight: 1
        $x_1_5 = "BANCOBRASILCOMBR" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AOO_2147705626_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOO"
        threat_id = "2147705626"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e9 34 02 00 00 83 ee 01 72 04 74 11 eb 1c 8d 45 f4 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? eb 0d 8d 45 f4 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 45 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 b4 50 33 c9 ba ?? ?? ?? ?? 66 b8 44 00 e8 ?? ?? ?? ?? 8b 45 b4 8d 55 b8 e8 ?? ?? ?? ?? 8b 55 b8 8d 45 e8 e8 ?? ?? ?? ?? 6a 00 8d 45 9c 50 33 c9 ba ?? ?? ?? ?? 66 b8 44 00 e8 ?? ?? ?? ?? 8b 55 9c 8d 45 a0 e8 ?? ?? ?? ?? 8b 45 a0 50 8d 45 94 50 33 c9 ba ?? ?? ?? ?? 66 b8 44 00}  //weight: 1, accuracy: Low
        $x_1_3 = {66 b8 44 00 e8 ?? ?? ?? ?? 8b 55 d0 8b 03 8b 08 ff 51 38 8d 45 cc 50 33 c9 ba ?? ?? ?? ?? 66 b8 44 00 e8 ?? ?? ?? ?? 8b 55 cc 8b 03 8b 08 ff 51 38 8d 45 c8 50 33 c9 ba ?? ?? ?? ?? 66 b8 44 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AOP_2147705652_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOP"
        threat_id = "2147705652"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "=DKUPDT=" wide //weight: 1
        $x_1_2 = {2e 00 63 00 70 00 6c 00 [0-22] 63 00 6d 00 64 00 20 00 2f 00 63 00}  //weight: 1, accuracy: Low
        $x_1_3 = {83 fb 01 75 0d 8d 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 fb 02 75 0d 8d 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 fb 03 75 0d 8d 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 55}  //weight: 1, accuracy: Low
        $x_1_4 = {74 05 83 e8 04 8b 00 89 45 ec 33 f6 8d 45 dc 50 b9 02 00 00 00 ba 01 00 00 00 8b 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Banker_AOP_2147705652_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOP"
        threat_id = "2147705652"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "=DKUPDT=" ascii //weight: 1
        $x_1_2 = {0f 84 2a 01 00 00 8d 95 5c fe ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff b5 5c fe ff ff 68 ?? ?? ?? ?? 8d 85 58 fe ff ff 50 ba 08 00 00 00 b8 04 00 00 00 e8 ?? ?? ?? ?? b1 01 33 d2 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {83 fb 01 75 0d 8d ?? ?? (b8|ba) ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 fb 02 75 0d 8d ?? ?? (b8|ba) ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 fb 03 75 0d 8d ?? ?? (b8|ba) ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AOQ_2147705656_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOQ"
        threat_id = "2147705656"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "808A8B9DA3C53FCB5B92D25A90" wide //weight: 1
        $x_1_2 = "99BB45D76DF370F07AFA44" wide //weight: 1
        $x_1_3 = "090F372F3FBA3DCB5797D658DD0B6EF80E57DD" wide //weight: 1
        $x_1_4 = {75 b6 ff 45 f8 ff 4d f4 75 8e 8d 4d ec ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 ec a1 ?? ?? ?? ?? 8b 00 8b 40 60 8b 80 98 00 00 00 33 c9 8b 18 ff 93 a4 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_Win32_Banker_AOQ_2147705656_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOQ"
        threat_id = "2147705656"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "valor=verde[" wide //weight: 1
        $x_1_2 = "tmp_hda" ascii //weight: 1
        $x_1_3 = "D344E70D3E82C3629A88F91FCB0E47E203" wide //weight: 1
        $x_1_4 = {75 1b 8d 55 f8 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f8 b2 01 e8 ?? ?? ?? ?? 84 c0 74 1a 8d 55 f4 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 f4 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 55 f0 b8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_5 = {85 c0 74 72 8d 95 c8 fd ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 95 c8 fd ff ff 8b 45 f8 05 ?? 03 00 00 e8 ?? ?? ?? ?? 8d 95 c4 fd ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 95 c4 fd ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 95 c0 fd ff ff b8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Banker_AOR_2147705690_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOR"
        threat_id = "2147705690"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "countdonwTMP_CAXALYTRUSP" ascii //weight: 1
        $x_1_2 = "countdonwTMP_SICRYNAST" ascii //weight: 1
        $x_1_3 = "countdonwTMP_SICOONASX" ascii //weight: 1
        $x_1_4 = "countdonwTMP_SANTYNY" ascii //weight: 1
        $x_1_5 = "countdonwTMP_BRASCOSK" ascii //weight: 1
        $x_1_6 = "HSBCALKRYTimer" ascii //weight: 1
        $x_1_7 = "SICOONASTimer" ascii //weight: 1
        $x_1_8 = "BRASCOSKTimer" ascii //weight: 1
        $x_1_9 = "imgSanta" ascii //weight: 1
        $x_1_10 = "imgBanri" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_Win32_Banker_AOS_2147705709_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOS"
        threat_id = "2147705709"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "4E979EA0D61E262936BD323DB5DD51C1C2C3BBB83AB5ACA6EF1377EF147183F71E" ascii //weight: 1
        $x_1_2 = {ba 02 00 00 80 8b 45 f8 e8 ?? ?? ?? ?? 8d 55 f4 b8 ?? ?? ?? ?? e8 ?? ?? 00 00 8b 55 f4 8b 45 f8 e8 ?? ?? ?? ?? 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 8d 55 f0 b8 ?? ?? ?? ?? e8 ?? ?? 00 00 8b 55 f0}  //weight: 1, accuracy: Low
        $x_1_3 = {ba 01 00 00 80 8b c3 e8 ?? ?? ?? ?? 8d 55 ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 ?? 33 c9 8b c3 e8 ?? ?? ?? ?? 8d 55 ?? 33 c0 e8 ?? ?? ?? ?? 8b 45 ?? 50 8d 55 ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 ?? 8b c3 59 e8 ?? ?? ?? ?? 8b c3 e8 ?? ?? ?? ?? 8d 55 ?? b8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_4 = {83 f8 07 7e 29 8d 95 ?? ff ff ff 8b 45 fc 8b 80 ?? 03 00 00 e8 ?? ?? ?? ?? 8b 95 ?? ff ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e9 00 01 00 00 ba ff c9 9a 3b b8 c7 6b 9f 06 e8 ?? ?? ?? ?? 8d 95 ?? ff ff ff e8 ?? ?? ?? ?? 8b 95 ?? ff ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 fc 8b 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Banker_AOT_2147705712_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOT"
        threat_id = "2147705712"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "maximusdecimus.cpl" ascii //weight: 1
        $x_1_2 = "serasa.com.br" ascii //weight: 1
        $x_1_3 = "cmd /k C:\\ProgramData\\java_update32.cmd" ascii //weight: 1
        $x_1_4 = "0.gif?3076455" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AOT_2147705712_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOT"
        threat_id = "2147705712"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b d0 80 c2 bf 80 ea 1a 73 0d 3c 4d 75 07 80 fb 48 75 02 b0 4e}  //weight: 2, accuracy: High
        $x_2_2 = {63 6d 64 20 2f 6b 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6a 61 76 61 5f 75 70 64 61 74 65 33 32 2e 63 6d 64 00}  //weight: 2, accuracy: High
        $x_2_3 = {50 72 6f 6a 65 63 74 36 36 36 00}  //weight: 2, accuracy: High
        $x_1_4 = {75 72 6c 3a 20 00}  //weight: 1, accuracy: High
        $x_1_5 = {75 72 6c 32 3a 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AOT_2147705712_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOT"
        threat_id = "2147705712"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "sitenet.serasa.com.br" ascii //weight: 5
        $x_5_2 = "cmd /k C:\\ProgramData\\java_update32.cmd" ascii //weight: 5
        $x_1_3 = "url2:" ascii //weight: 1
        $x_1_4 = "win:" ascii //weight: 1
        $x_1_5 = "IExplore_Explorer_Server" ascii //weight: 1
        $x_1_6 = {8b 55 f0 33 db 8a 5c 10 ff 33 5d e4 3b f3 7d 04 2b de eb 0c 3b f3 7c 08 81 c3 ff 00 00 00 2b de 8d 45 d4 8b d3 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AOT_2147705712_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOT"
        threat_id = "2147705712"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 75 72 6c 3a 20 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-16] 20 75 72 6c 32 3a 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = {66 ba 57 00 a1 ?? ?? ?? ?? e8 08 fc ff ff 68 4d 01 00 00 e8 ?? ?? ?? ?? 6a 00 8d 55 f4 b8 ?? ?? ?? ?? e8 a7 f7 ff ff ff 75 f4 68 ?? ?? ?? ?? ff 75 fc 8d 45 f8 ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 45 f8 e8 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {75 17 8d 55 d4 8b c3 e8 e4 f1 ff ff 8b 55 d4 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 33 c9 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 f4 8b 45 f4 c7 80 9c 00 00 00 e8 03 00 00 8d 55 d0 b8 ?? ?? ?? ?? e8 06 ca ff ff 8b 55 d0 8d 45 f0 8b 4d f8 e8 ?? ?? ?? ?? 8d 55 cc b8 ?? ?? ?? ?? e8 eb c9 ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 08 c7 40 fc c8 00 00 00 8b 45 08 ff 40 fc 8d 45 e8 50 8b 45 fc 50 8b 00 ff 50 20 85 c0 0f 85 37 01 00 00 83 7d e8 00 0f 8e 2d 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_Win32_Banker_AOU_2147705915_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOU"
        threat_id = "2147705915"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 85 54 f0 ff ff 50 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 8b 85 54 f0 ff ff 50 8d 85 4c f0 ff ff 8d 95 5a f0 ff ff b9 d1 07 00 00 e8 ?? ?? ?? ?? 8b 85 4c f0 ff ff 8d 95 50 f0 ff ff e8 ?? ?? ?? ?? 8b 95 50 f0 ff ff b9 01 00 00 00 58 e8 ?? ?? ?? ?? 85 c0 0f 8f c6 00 00 00 68 ?? ?? ?? ?? 8d 85 48 f0 ff ff 50 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? 8b 45 fc}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 01 00 00 00 58 e8 ?? ?? ?? ?? 85 c0 7f 65 68 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 50 8d 85 ?? ?? ?? ?? 8d 95 5a f0 ff ff b9 d1 07 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AOX_2147706061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOX"
        threat_id = "2147706061"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 65 00 64 00 65 00 6e 00 74 00 65 00 [0-16] 53 00 61 00 63 00 61 00 64 00 6f 00 [0-16] 42 00 6f 00 6c 00 65 00 74 00 6f 00}  //weight: 1, accuracy: Low
        $x_1_2 = "TInetGetBol" ascii //weight: 1
        $x_1_3 = "ACAO=GET" wide //weight: 1
        $x_1_4 = "ACAO=POST" wide //weight: 1
        $x_1_5 = ".americanas.com.br/bankslip" wide //weight: 1
        $x_1_6 = "\\UCentral.pas" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Banker_AOX_2147706061_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOX"
        threat_id = "2147706061"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ieInyectaEspecial" ascii //weight: 1
        $x_1_2 = "[/iny-formini]" wide //weight: 1
        $x_1_3 = "form.action = \"$$getvarrtini$$\";" wide //weight: 1
        $x_1_4 = "revisarVentanas" ascii //weight: 1
        $x_1_5 = "var element1 = document.createElement(\"input\");" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_AOY_2147706101_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.AOY"
        threat_id = "2147706101"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "r.leandro.santos2015@uol.com.br" wide //weight: 1
        $x_1_2 = "dusterifos2020@gmail.com" wide //weight: 1
        $x_1_3 = "agoraachoquevaiavisonovo@gmail.com" wide //weight: 1
        $x_1_4 = "senderenvioemail.tmp" wide //weight: 1
        $x_1_5 = "maria2089" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Banker_APB_2147706651_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.APB"
        threat_id = "2147706651"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6D656761746F6E69636132303031" wide //weight: 1
        $x_1_2 = "NvJgaNgN2jU1XPNa+mYVIQ==" wide //weight: 1
        $x_1_3 = "49696D704461646F73" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_APC_2147706689_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.APC"
        threat_id = "2147706689"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {c7 45 f0 01 00 00 00 8b 45 e4 8b 55 f0 0f b7 44 50 fe 33 45 dc 89 45 d8 8b 45 d8 3b 45 ec 7f 10 8b 45 d8 05 ff 00 00 00 2b 45 ec 89 45 d8 eb 06}  //weight: 3, accuracy: High
        $x_1_2 = {49 00 54 00 41 00 43 00 4f 00 44 00 49 00 47 00 4f 00 7c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "TFITALIE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_APD_2147706725_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.APD"
        threat_id = "2147706725"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AG3ND4:" ascii //weight: 1
        $x_1_2 = "C0NT4T:" ascii //weight: 1
        $x_1_3 = "CELULAR:" ascii //weight: 1
        $x_1_4 = "S3NH46:" ascii //weight: 1
        $x_1_5 = "S3NH48:" ascii //weight: 1
        $x_1_6 = "S3NH44:" ascii //weight: 1
        $x_1_7 = "CARTAO:" ascii //weight: 1
        $x_1_8 = "CCV DO CARTAO:" ascii //weight: 1
        $x_1_9 = "chrome.exe" ascii //weight: 1
        $x_1_10 = "GbpSV.exe" ascii //weight: 1
        $x_1_11 = "023- Conta CAIXA F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_Win32_Banker_APE_2147707112_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.APE"
        threat_id = "2147707112"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "==ESET" wide //weight: 10
        $x_10_2 = "= Software" wide //weight: 10
        $x_1_3 = "\\GbPlugin" wide //weight: 1
        $x_1_4 = "\\Scpad" wide //weight: 1
        $x_1_5 = "[Be_Be]" wide //weight: 1
        $x_1_6 = "[Ita_u]" wide //weight: 1
        $x_1_7 = "[Ama_zonia]" wide //weight: 1
        $x_1_8 = "[Uni_cred]" wide //weight: 1
        $x_1_9 = "[Mencan_til]" wide //weight: 1
        $x_1_10 = "[Info_seg]" wide //weight: 1
        $x_1_11 = "gbiehamz.dll" wide //weight: 1
        $x_1_12 = "gbiehuni.dll" wide //weight: 1
        $x_1_13 = "No Pls" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_APG_2147708935_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.APG"
        threat_id = "2147708935"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 53 45 4d 50 52 45 [0-1] 4f 4e 4c 49 4e 45 5d}  //weight: 1, accuracy: Low
        $x_1_2 = {5b 4d 4f 55 53 45 [0-1] 44 49 52 45 49 54 4f 5d}  //weight: 1, accuracy: Low
        $x_1_3 = "04BRA" ascii //weight: 1
        $x_1_4 = "07SICOO" ascii //weight: 1
        $x_1_5 = "LOGS=>" ascii //weight: 1
        $x_1_6 = {00 47 42 50 4c 55 47 49 4e 00}  //weight: 1, accuracy: High
        $x_1_7 = {49 45 00 00 46 49 52 45 46 4f 58 2e 45 58 45}  //weight: 1, accuracy: High
        $x_1_8 = {42 41 49 44 55 [0-16] 41 56 47 [0-16] 41 56 41 53 54}  //weight: 1, accuracy: Low
        $x_1_9 = {33 d2 e8 64 7b fe ff 66 83 cb 08 33 c0 5a 59 59}  //weight: 1, accuracy: High
        $x_1_10 = {fe ca 74 10 eb 5c e8 84 c8 ff ff eb 55 e8 a5 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Banker_APH_2147708936_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.APH"
        threat_id = "2147708936"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 79 73 74 65 6d 32 32 00}  //weight: 1, accuracy: High
        $x_1_2 = {54 6f 64 6f 73 [0-16] 53 59 53 54 45 4d}  //weight: 1, accuracy: Low
        $x_1_3 = "GbpSv.exe\" /T /E /C /P" ascii //weight: 1
        $x_1_4 = "wsftprp64.sys\" /T /E /C /P" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_APJ_2147712606_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.APJ"
        threat_id = "2147712606"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "winupdate.dat" wide //weight: 1
        $x_1_2 = {53 00 4f 00 4d 00 5f 00 46 00 52 00 45 00 56 00 4f 00 00 00 4d 00 50 00 36 00 46 00 49 00 4c 00 45 00 31 00}  //weight: 1, accuracy: High
        $x_1_3 = "regis.dat" wide //weight: 1
        $x_1_4 = {0f b7 44 50 fe 33 45 ?? 89 45 ?? 8b 45 ?? 3b 45 ?? 7f ?? 8b 45 ?? 05 ff 00 00 00 2b 45 ?? 89 45 ?? eb}  //weight: 1, accuracy: Low
        $x_1_5 = "<|TAMANHO|>" wide //weight: 1
        $x_1_6 = "<|okok|>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Banker_APK_2147712611_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.APK"
        threat_id = "2147712611"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Winge.exe" ascii //weight: 1
        $x_1_2 = "Windp.exe" ascii //weight: 1
        $x_1_3 = {53 00 4f 00 4d 00 5f 00 52 00 4f 00 43 00 4b 00 00 00 00 00 4d 00 50 00 33 00 46 00 49 00 4c 00 45 00 31 00}  //weight: 1, accuracy: High
        $x_1_4 = "Plugin de seguran" ascii //weight: 1
        $x_1_5 = {0f b7 44 50 fe 33 45 ?? 89 45 ?? 8b 45 ?? 3b 45 ?? 7f ?? 8b 45 ?? 05 ff 00 00 00 2b 45 ?? 89 45 ?? eb}  //weight: 1, accuracy: Low
        $x_1_6 = "<|TAMANHO|>" wide //weight: 1
        $x_1_7 = "<|okok|>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Banker_APM_2147716145_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.APM"
        threat_id = "2147716145"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 40 1f 00 00 e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 95 18 ff ff ff a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 85 18 ff ff ff e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 85 c0 76 23}  //weight: 1, accuracy: Low
        $x_1_2 = {be 0f 00 00 00 8d 8d 30 ff ff ff 8b d6 8b c3 8b 38 ff 57 0c 8b 85 30 ff ff ff 8d 95 34 ff ff ff e8 ?? ?? ?? ?? 8b 85 34 ff ff ff 8d 95 38 ff ff ff e8 ?? ?? ?? ?? 8b 95 38 ff ff ff a1 ?? ?? ?? ?? 8b 08 ff 51 38 46 81 fe 0f 01 00 00 75 b6}  //weight: 1, accuracy: Low
        $x_1_3 = {68 58 1b 00 00 e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? e9 d4 fe ff ff 33 c0 5a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_APN_2147719157_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.APN"
        threat_id = "2147719157"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2e 00 62 00 72 00 61 00 64 00 65 00 73 00 63 00 6f 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 [0-2] 31 00 ?? ?? ?? ?? 2e 00 ?? ?? ?? ?? 2e 00 ?? ?? ?? ?? ?? ?? 2e 00 ?? ?? ?? ?? ?? ?? 20 00 [0-48] 2e 00 62 00 72 00 [0-2] 31 00 01 2e 00 02 2e 00 03 2e 00 04 20 00 [0-48] 2e 00 62 00 72 00 [0-2] 31 00 01 2e 00 02 2e 00 03 2e 00 04 20 00 [0-48] 2e 00 62 00 72 00}  //weight: 4, accuracy: Low
        $x_4_2 = {2e 00 62 00 61 00 6e 00 63 00 6f 00 64 00 6f 00 62 00 72 00 61 00 73 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 [0-2] 31 00 ?? ?? ?? ?? 2e 00 ?? ?? ?? ?? 2e 00 ?? ?? ?? ?? ?? ?? 2e 00 ?? ?? ?? ?? ?? ?? 20 00 [0-48] 2e 00 62 00 72 00 [0-2] 31 00 01 2e 00 02 2e 00 03 2e 00 04 20 00 [0-48] 2e 00 62 00 72 00 [0-2] 31 00 01 2e 00 02 2e 00 03 2e 00 04 20 00 [0-48] 2e 00 62 00 72 00}  //weight: 4, accuracy: Low
        $x_4_3 = {2e 00 69 00 74 00 61 00 75 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 [0-2] 31 00 ?? ?? ?? ?? 2e 00 ?? ?? ?? ?? 2e 00 ?? ?? ?? ?? ?? ?? 2e 00 ?? ?? ?? ?? ?? ?? 20 00 [0-48] 2e 00 62 00 72 00 [0-2] 31 00 01 2e 00 02 2e 00 03 2e 00 04 20 00 [0-48] 2e 00 62 00 72 00 [0-2] 31 00 01 2e 00 02 2e 00 03 2e 00 04 20 00 [0-48] 2e 00 62 00 72 00}  //weight: 4, accuracy: Low
        $x_1_4 = "\\drivers\\etc\\hosts" wide //weight: 1
        $x_1_5 = {de 0b 07 2c 07 07 6f ?? 00 00 0a 00 dc 7e ?? 00 00 0a 72 ?? ?? 00 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_VCZ_2147720015_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VCZ!bit"
        threat_id = "2147720015"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "smtps.uol.com.br" wide //weight: 10
        $x_2_2 = "@gmail.com" wide //weight: 2
        $x_2_3 = "avastui.exe" wide //weight: 2
        $x_2_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_1_5 = "internetbankingcaixa" wide //weight: 1
        $x_1_6 = "internet banking" wide //weight: 1
        $x_1_7 = "bradesco s/a" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_VDA_2147720483_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VDA!bit"
        threat_id = "2147720483"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 72 6f 6a 65 63 74 32 5f 58 45 35 2e 64 6c 6c 00 54 4d 65 74 68 6f 64 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 49 6e 74 65 72 63 65 70 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_XF_2147721117_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.XF!bit"
        threat_id = "2147721117"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 06 88 08 8b 4d fc 42 40 3b d1 72 f2}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 07 88 10 41 40 3b 4d fc 72 f4}  //weight: 1, accuracy: High
        $x_2_3 = {8b f1 c1 ee ?? 03 35 ?? ?? ?? ?? 8b f9 c1 e7 ?? 03 3d ?? ?? ?? ?? 33 f7 8d 3c 0a 33 f7 2b c6 8b f0 c1 ee ?? 03 35 ?? ?? ?? ?? 8b f8 c1 e7 ?? 03 3d ?? ?? ?? ?? 33 f7 8d 3c 02 33 f7 2b ce}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_VDB_2147732938_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VDB!bit"
        threat_id = "2147732938"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 11 33 c0 3a 54 04 ?? 74 08 40 83 f8 43 72 f4 eb 10 40 33 d2 bf 43 00 00 00 f7 f7 8a 54 14 ?? 88 11}  //weight: 1, accuracy: Low
        $x_1_2 = {68 e8 03 00 00 ff 15 ?? ?? ?? ?? 56 ff d5 8b 0d ?? ?? ?? ?? a3 ?? ?? ?? ?? 2b c1 83 c4 04 99 33 c2 2b c2 83 f8 5a 7c d8}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 54 04 10 30 14 01 40 3b c6 7c f4}  //weight: 1, accuracy: High
        $x_1_4 = "content-type: Clipboard" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_6 = "time: %04d%02d%02d%02d%02d%02d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_VDB_2147732938_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VDB!bit"
        threat_id = "2147732938"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "112"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Software\\Borland\\Delphi\\Locales" wide //weight: 100
        $x_1_2 = "<|Info|>" wide //weight: 1
        $x_1_3 = "<|SocketMain|>" wide //weight: 1
        $x_1_4 = {00 00 5c 00 61 00 76 00 69 00 73 00 6f 00 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: High
        $x_1_5 = "http://allegoritim.3utilities.com/allgor/n.php?npc=" wide //weight: 1
        $x_10_6 = "5C536F6674776172655C4D6963726F736F66745C57696E646F77735C43757272656E7456657273696F6E5C52756E" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banker_VDE_2147733793_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.VDE!bit"
        threat_id = "2147733793"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 10 c1 c2 07 40 49 75 f7}  //weight: 1, accuracy: High
        $x_1_2 = {8b d0 c6 05 ?? ?? ?? ?? 57 c6 05 ?? ?? ?? ?? 6f c6 05 ?? ?? ?? ?? 77 c6 05 ?? ?? ?? ?? 36 c6 05 ?? ?? ?? ?? 34 c6 05 ?? ?? ?? ?? 44 c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 73 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 62 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 65}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c6 24 0f 3c 0a 1c 69 2f 88 04 11 c1 ee 04 49 79 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_BS_2147751940_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.BS!MTB"
        threat_id = "2147751940"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {29 f6 2b 37 f7 de 83 ef fc 83 ee 34 c1 ce 08 29 d6 83 ee 01 29 d2 29 f2 f7 da c1 c2 09 d1 ca 6a ff 8f 01 21 31 83 e9 fc 83 eb 03 8d 5b ff 83 fb 00 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_2147799879_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker"
        threat_id = "2147799879"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.xiuzhe.com/ddvan.exe" ascii //weight: 1
        $x_1_2 = "userid=" ascii //weight: 1
        $x_1_3 = "password=" ascii //weight: 1
        $x_1_4 = "C:\\windows\\sysinfo.ini" wide //weight: 1
        $x_1_5 = "C:\\windows\\ebx1e1.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_2147799879_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker"
        threat_id = "2147799879"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 1
        $x_1_2 = "dsProxyDetecting" ascii //weight: 1
        $x_1_3 = "RCPT TO" ascii //weight: 1
        $x_1_4 = "MAIL FROM" ascii //weight: 1
        $x_1_5 = "mysql1.100ws.com" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_7 = "WSAAsyncGetHostByName" ascii //weight: 1
        $x_1_8 = "GetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_2147799879_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker"
        threat_id = "2147799879"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shell\\BATLE_SOURCE\\SampleService_run_shellcode_from-memory10-02-2016\\Release\\SampleService.pdb" ascii //weight: 1
        $x_1_2 = "JAVA: ServiceCtrlHandler: SERVICE_CONTROL_STOP Request" wide //weight: 1
        $x_1_3 = "Users\\DNS\\Documents\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_2147799879_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker"
        threat_id = "2147799879"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 1
        $x_1_2 = "YourFileHost.com" ascii //weight: 1
        $x_1_3 = "HostFilez.com" ascii //weight: 1
        $x_1_4 = "updater.dll" ascii //weight: 1
        $x_1_5 = "audiohq.exe" ascii //weight: 1
        $x_1_6 = "c:\\arquivos de programas\\internet explorer\\iexplore.exe   http://www.youtube.com/watch?v=Vjp7vgj119s" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_8 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_9 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_2147799879_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker"
        threat_id = "2147799879"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YUQL23KL23DF90WI5E1JAS467NMCXXL6JAOAUWWMCL0AOMM4A4VZYW9KHJUI2347EJHJKDF3424SKL" ascii //weight: 1
        $x_1_2 = "BB244BAFCF375C90E42E50A6DF2D6889E52351B3CF2241404040B63DB138A3DB2747BF3741A7CC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_Win32_Banker_2147799879_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker"
        threat_id = "2147799879"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ABN AMRO Bank" ascii //weight: 1
        $x_1_2 = "Banco do Nordeste Brasileiro" ascii //weight: 1
        $x_1_3 = "Banco Cooperativo do Brasil" ascii //weight: 1
        $x_1_4 = "Banco do Estado de Pernambuco" ascii //weight: 1
        $x_1_5 = "Banco do Estado de Sergipe" ascii //weight: 1
        $x_1_6 = "Banco do Estado do Paran" ascii //weight: 1
        $x_1_7 = "Banco do Estado do Rio Grande do Sul" ascii //weight: 1
        $x_1_8 = "Banco Cidade" ascii //weight: 1
        $x_1_9 = "Banco Citibank" ascii //weight: 1
        $x_1_10 = "Banco Credibel" ascii //weight: 1
        $x_1_11 = "Banco Daycoval" ascii //weight: 1
        $x_1_12 = "Banco do Brasil" ascii //weight: 1
        $x_1_13 = "HSBC Bamerindus" ascii //weight: 1
        $x_1_14 = "Banco Mercantil do Brasil" ascii //weight: 1
        $x_1_15 = "Banco Nossa Caixa" ascii //weight: 1
        $x_1_16 = "Banco Cooperativo SICREDI" ascii //weight: 1
        $x_1_17 = "Base IR e Gerador de INSS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_2147799879_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker"
        threat_id = "2147799879"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VegasCard" ascii //weight: 1
        $x_1_2 = "CartaoEvangelico" ascii //weight: 1
        $x_1_3 = "Minascred" ascii //weight: 1
        $x_1_4 = "Bilhete Unico" ascii //weight: 1
        $x_1_5 = "Banco Panamericano" ascii //weight: 1
        $x_1_6 = "Check Express_2" ascii //weight: 1
        $x_1_7 = "Bradesco Private" ascii //weight: 1
        $x_1_8 = "Cabal Argentina" ascii //weight: 1
        $x_1_9 = "Banco Provincial" ascii //weight: 1
        $x_1_10 = "Amex Mexico" ascii //weight: 1
        $x_1_11 = "Brasil Card" ascii //weight: 1
        $x_1_12 = "Telenet" ascii //weight: 1
        $x_1_13 = "Citibank" ascii //weight: 1
        $x_1_14 = "HiperCard" ascii //weight: 1
        $x_1_15 = "E-Capture" ascii //weight: 1
        $x_1_16 = "Accor Services" ascii //weight: 1
        $x_1_17 = "Yamada" ascii //weight: 1
        $x_1_18 = "AutorizBonus" ascii //weight: 1
        $x_1_19 = "MultiCheque" ascii //weight: 1
        $x_1_20 = "OnlyVisa" ascii //weight: 1
        $x_1_21 = "sitonlyvisa.exe" ascii //weight: 1
        $x_1_22 = "TecBan OnLine" ascii //weight: 1
        $x_1_23 = "TecBan Host-Host" ascii //weight: 1
        $x_1_24 = "CreditBureau" ascii //weight: 1
        $x_1_25 = "Roteador de Correspondente Bancario" ascii //weight: 1
        $x_1_26 = "BOD Debito" ascii //weight: 1
        $x_1_27 = "BOD Credito" ascii //weight: 1
        $x_1_28 = "PaySmartID" ascii //weight: 1
        $x_1_29 = "BrazilianCard" ascii //weight: 1
        $x_1_30 = "C.B. Corban Software Express" ascii //weight: 1
        $x_1_31 = "sitepaygift" ascii //weight: 1
        $x_1_32 = "EPAYGIFT" ascii //weight: 1
        $x_1_33 = "SitBanescard" ascii //weight: 1
        $x_1_34 = "BANESCAR" ascii //weight: 1
        $x_1_35 = "Amex Internacional" ascii //weight: 1
        $x_1_36 = "Banco Santos" ascii //weight: 1
        $x_1_37 = "Cheque Cardapio" ascii //weight: 1
        $x_1_38 = "Associacao Comercial SP" ascii //weight: 1
        $x_1_39 = "sitwayup.exe" ascii //weight: 1
        $x_1_40 = "sitcarto.exe" ascii //weight: 1
        $x_1_41 = "sitonebox.exe" ascii //weight: 1
        $x_1_42 = "sitmaxxicard.exe" ascii //weight: 1
        $x_1_43 = "sitpaysmartid.exe" ascii //weight: 1
        $x_1_44 = "sitglobalsaude.exe" ascii //weight: 1
        $x_1_45 = "sitcardse.exe" ascii //weight: 1
        $x_1_46 = "sitbancred.exe" ascii //weight: 1
        $x_1_47 = "sitsimcred.exe" ascii //weight: 1
        $x_1_48 = "sitvisapassfirst.exe" ascii //weight: 1
        $x_1_49 = "simcomuincomm.exe" ascii //weight: 1
        $x_1_50 = "sitincomm.exe" ascii //weight: 1
        $x_1_51 = "sitltmraizen.exe" ascii //weight: 1
        $x_1_52 = "simcomumexicoprosa.exe" ascii //weight: 1
        $x_1_53 = "Serasa Autorizador Credito" ascii //weight: 1
        $x_1_54 = "Banco GE Capital" ascii //weight: 1
        $x_1_55 = "Cartao Presente Marisa" ascii //weight: 1
        $x_1_56 = "Banco Pottencial" ascii //weight: 1
        $n_100_57 = "/sitef/./config/sitef.ini" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ARD_2147837908_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ARD!MTB"
        threat_id = "2147837908"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 46 04 8b 56 08 33 c9 8a 0c 10 ff 46 08 83 46 10 01 83 56 14 00 84 db}  //weight: 1, accuracy: High
        $x_1_2 = {eb 7d 8b 44 24 0c 88 0c 28 45 83 fd 03 75 19 8b}  //weight: 1, accuracy: High
        $x_1_3 = "MapVirtualKey" ascii //weight: 1
        $x_1_4 = "GetKeyNameTextA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banker_ARC_2147899444_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banker.ARC!MTB"
        threat_id = "2147899444"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ctrl.mtx.rbt" ascii //weight: 1
        $x_1_2 = "KillTimer" ascii //weight: 1
        $x_1_3 = "MapVirtualKeyA" ascii //weight: 1
        $x_1_4 = "GetKeyNameTextA" ascii //weight: 1
        $x_1_5 = {db 6c 24 30 de c9 db 7c 24 3c 9b db 2d ?? ?? ?? ?? e8 ?? ?? ?? ?? db 6c 24 3c de c9 dd d8 4b 75 82 83 c4 48 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

