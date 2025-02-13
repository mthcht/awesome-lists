rule Worm_Win32_Autorun_A_2147596271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.A"
        threat_id = "2147596271"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\folder_x\\File Folder.vbp" wide //weight: 5
        $x_5_2 = "c:\\services.exe" wide //weight: 5
        $x_2_3 = "\\Command=auto.exe" wide //weight: 2
        $x_2_4 = "NeverShowExt" wide //weight: 2
        $x_1_5 = "\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_1_6 = "\\Policies\\Explorer\\Run" wide //weight: 1
        $x_1_7 = "\\Windows\\CurrentVersion\\Policies" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_C_2147597127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.C"
        threat_id = "2147597127"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 00 66 00 61 00 63 00 6b 00 20 00 4d 00 73 00 6e 00 5c 00 [0-32] 76 00 62 00 53 00 65 00 6e 00 64 00 4d 00 61 00 69 00 6c 00 2e 00 76 00 62 00 70 00}  //weight: 10, accuracy: Low
        $x_10_2 = {56 49 44 49 4f 48 4f 4d 45 00 33 33 66 00 33 33 56 49 44 49 4f 20 48 4f 4d 45 00}  //weight: 10, accuracy: High
        $x_1_3 = "clsSendMail" ascii //weight: 1
        $x_1_4 = "copytodrives" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_C_2147597127_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.C"
        threat_id = "2147597127"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "McRegWizz" wide //weight: 1
        $x_1_4 = "autorun.inf" wide //weight: 1
        $x_1_5 = "[AutoRun]" wide //weight: 1
        $x_1_6 = "shellexecute=McRegWizz.exe" wide //weight: 1
        $x_1_7 = "shell\\Auto\\command=McRegWizz.exe" wide //weight: 1
        $x_1_8 = "HKEY_DYN_DATA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_D_2147597187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.D"
        threat_id = "2147597187"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "85"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Hook.dll" ascii //weight: 10
        $x_10_2 = "DllCanUnloadNow" ascii //weight: 10
        $x_10_3 = "DllRegisterServer" ascii //weight: 10
        $x_10_4 = "MsgHookOff" ascii //weight: 10
        $x_10_5 = "MsgHookOn" ascii //weight: 10
        $x_10_6 = "CallNextHookEx" ascii //weight: 10
        $x_10_7 = "InternetReadFile" ascii //weight: 10
        $x_10_8 = "InternetOpen" ascii //weight: 10
        $x_1_9 = "[autorun]" ascii //weight: 1
        $x_1_10 = "open=CMD.EXE" ascii //weight: 1
        $x_1_11 = "shellexecute=CMD.EXE" ascii //weight: 1
        $x_1_12 = "shell\\Auto\\command=CMD.EXE" ascii //weight: 1
        $x_1_13 = "Software\\SetVer\\ver" ascii //weight: 1
        $x_1_14 = "Explorer.Exe" ascii //weight: 1
        $x_1_15 = "Verclsid.eXE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_D_2147597187_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.D"
        threat_id = "2147597187"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "[Autorun]" wide //weight: 10
        $x_10_2 = "\\Autorun.inf" wide //weight: 10
        $x_10_3 = {6f 00 70 00 65 00 6e 00 3d 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_10_4 = "startupfolder.com" wide //weight: 10
        $x_1_5 = "wscript.shell" wide //weight: 1
        $x_1_6 = "hkey_local_machine\\software\\microsoft\\windows\\currentversion\\run\\" wide //weight: 1
        $x_1_7 = "SHGetSpecialFolderLocation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_K_2147598172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.K"
        threat_id = "2147598172"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "212"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SeShutdownPrivilege" wide //weight: 100
        $x_100_2 = "CreateToolhelp32Snapshot" ascii //weight: 100
        $x_10_3 = "Desktop\\Russia\\Error.vbp" wide //weight: 10
        $x_10_4 = "Windows Firewall  has detected [W32RontokBro@mm   as Security risk that requires your attention. " ascii //weight: 10
        $x_1_5 = "McAfee.com\\VSO\\Mcshield.exe" wide //weight: 1
        $x_1_6 = "McAfee.com\\VSO\\McVSEscn.exe" wide //weight: 1
        $x_1_7 = "ESET\\nod32.exe" wide //weight: 1
        $x_1_8 = "explorer.exe \"http://security.symantec.com" wide //weight: 1
        $x_1_9 = "explorer.exe \"http://www.symantec.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_L_2147598175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.L"
        threat_id = "2147598175"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "211"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "VirtualProtect" ascii //weight: 100
        $x_100_2 = "URLDownloadToFileA" ascii //weight: 100
        $x_10_3 = "svchs0t.exe" ascii //weight: 10
        $x_10_4 = "http://xx.522love.cn/tool/down" ascii //weight: 10
        $x_1_5 = "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL\" /v CheckedValue /t REG_SZ /d 0 /f" ascii //weight: 1
        $x_1_6 = "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\NOHIDDEN\" /v CheckedValue /t REG_dword /d 00000002 /f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_G_2147598469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.G"
        threat_id = "2147598469"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "137"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "QueryServiceConfig2" ascii //weight: 10
        $x_10_2 = "ChangeServiceConfig2" ascii //weight: 10
        $x_10_3 = "drivers/klif.sys" ascii //weight: 10
        $x_1_4 = ":\\AutoRun.inf" ascii //weight: 1
        $x_1_5 = "NoDriveTypeAutoRun" ascii //weight: 1
        $x_1_6 = "[AutoRun]" ascii //weight: 1
        $x_1_7 = "shellexecute=" ascii //weight: 1
        $x_1_8 = "shell\\Auto\\command=" ascii //weight: 1
        $x_1_9 = "serverie" ascii //weight: 1
        $x_1_10 = "cmd /c date" ascii //weight: 1
        $x_1_11 = "\\program files\\internet explorer\\IEXPLORE.EXE" ascii //weight: 1
        $x_100_12 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_N_2147598582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.N"
        threat_id = "2147598582"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "xcopy thG.exe %SYSTEMROOT%" ascii //weight: 10
        $x_10_2 = "echo shellexecute=thG.exe >> autorun.inf" ascii //weight: 10
        $x_10_3 = "wget \"http://virae.org/trojanhorsegallery/get.php" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_X_2147599578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.X"
        threat_id = "2147599578"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\bluestar\\desktop\\" wide //weight: 10
        $x_10_2 = "windir" wide //weight: 10
        $x_10_3 = "explorer .\\" wide //weight: 10
        $x_10_4 = "Zombie_GetTypeInfoCount" ascii //weight: 10
        $x_10_5 = "VB98\\VB6.OLB" ascii //weight: 10
        $x_1_6 = "scvhost.exe" wide //weight: 1
        $x_1_7 = "svchost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_Y_2147600065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.Y"
        threat_id = "2147600065"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KAV32.exe" ascii //weight: 1
        $x_1_2 = "avp.com" ascii //weight: 1
        $x_1_3 = "taskmgr.exe" ascii //weight: 1
        $x_1_4 = "svch0st.exe" ascii //weight: 1
        $x_1_5 = "shell\\open\\Command=" ascii //weight: 1
        $x_1_6 = "shell\\explore\\command=" ascii //weight: 1
        $x_1_7 = "\\autorun.inf" ascii //weight: 1
        $x_1_8 = "Flower.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_NV_2147600202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.NV"
        threat_id = "2147600202"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Scripting.Filesystemobject" wide //weight: 1
        $x_1_2 = "InternetExplorer.Application" wide //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\Advanced\\Folder\\Hidden\\SHOWALL" wide //weight: 1
        $x_1_4 = "\\*.txt" wide //weight: 1
        $x_1_5 = "Start Page" wide //weight: 1
        $x_1_6 = "www.814e.com" wide //weight: 1
        $x_1_7 = "8koo.cn/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_NW_2147600414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.NW"
        threat_id = "2147600414"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dung_DakNong" wide //weight: 1
        $x_1_2 = "C:\\WINDOWS\\Sys.exe" wide //weight: 1
        $x_1_3 = "shell\\Auto\\command=RavMonE.exe" wide //weight: 1
        $x_1_4 = "New Folder.exe" wide //weight: 1
        $x_1_5 = "/johnteen/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_NY_2147600540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.NY"
        threat_id = "2147600540"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 7a 6f 6b 72 61 53 69 7a 6f 6b 72 61 53 00 00 ff ff ff ff 09 00 00 00 72 65 62 79 63 2e 74 6d 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "dawin.exe" ascii //weight: 1
        $x_1_3 = {4f 43 61 63 68 65 00 00 ff ff ff ff 2f 00 00 00 2e 5c 4d 53 4f 43 61 63 68 65 5c 39 30 30 30 30 38 30 34 2d 36 30 30 30 2d 31 31 44 33 2d 38 43 46 45 2d 30 31 35 30 30 34 38 33 38 33 43 39 00 ff ff ff ff 0b 00 00 00 61 75 74 6f 72 75 6e 2e 69 6e 66 00 ff ff ff ff 09 00 00 00 5b 41 75 74 6f 52 75 6e 5d 00 00 00 ff ff ff ff 43 00 00 00 6f 70 65 6e 3d 2e 5c 4d 53 4f 43 61 63 68 65 5c 39 30 30 30 30 38 30 34 2d 36 30 30 30 2d 31 31 44 33 2d 38 43 46 45 2d 30 31 35 30 30 34 38 33 38 33 43 39 5c 4b 42 39 31 35 38 36 35 2e 65 78 65 20 2e 00 ff ff ff ff 4b 00 00 00 73 68 65 6c}  //weight: 1, accuracy: High
        $x_1_4 = {6a 05 68 14 ca 40 00 8d 45 e0 e8 cd a3 ff ff 8b 45 e0 8a 10 8d 45 e4 e8 24 79 ff ff ff 75 e4 68 30 ca 40 00 8d 45 e8 ba 03 00 00 00 e8 77 7a ff ff 8b 45 e8 e8 a7 7b ff ff 50 e8 79 90 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_OC_2147601378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.OC"
        threat_id = "2147601378"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 e8 c6 07 fb ff 83 e8 02 0f 85 f6 02 00 00 8b 45 f4 e8 51 f8 ff ff 84 c0 0f 84 e6 02 00 00 33 c0 55 68 ef 5b 45 00 64 ff 30 64 89 20 8d 45 e8 b9 84 5c 45 00 8b 55 f4 e8 23 ea fa ff 8b 45 e8 e8 83 2b fb ff 84 c0 0f 85 92 00 00 00 33 c0 55 68 d1 59 45 00 64 ff 30 64 89 20 b3 01 80 fb 01 f5 1b c0 50 8d 45 e4 b9 84 5c 45 00 8b 55 f4 e8 ec e9 fa ff 8b 45 e4 e8 98 eb fa ff 50 8d 55 e0 a1 a0 70 45 00 8b 00 e8 ac cf ff ff 8b 45 e0 e8 80 eb fa ff 50 e8 72 06 fb ff 8d 45 dc b9 84 5c 45 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 6c 6c 2e 65 78 65 00 ff ff ff ff 2e 00 00 00 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 72 75 6e}  //weight: 1, accuracy: High
        $x_1_3 = {64 72 69 76 65 72 2e 65 78 65 00 00 ff ff ff ff 0b 00 00 00 61 75 74 6f 72 75 6e 2e 69 6e 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_OD_2147601486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.OD"
        threat_id = "2147601486"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\LapTrinh_VB6 C++\\chip VB6\\ChangeWallPaper\\Change on Lan\\chip_and_you.vbp" wide //weight: 1
        $x_1_2 = "shell\\Auto\\command=chip_and_you.exe" ascii //weight: 1
        $x_1_3 = "Thay doi gia tri Registry khong thanh cong." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_OE_2147601494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.OE"
        threat_id = "2147601494"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Config\\nvscv32.vbp" wide //weight: 1
        $x_1_2 = "shell\\open\\Command=Config.exe" wide //weight: 1
        $x_1_3 = ":\\autorun.inf" wide //weight: 1
        $x_1_4 = "Program Files\\Internet Explorer\\Connection Wizard\\SVCHOST.EXE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AJ_2147601511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AJ"
        threat_id = "2147601511"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\WINDOWS\\system32\\Emulador_PlayStation_II.exe" wide //weight: 1
        $x_1_2 = {5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 46 00 6f 00 6c 00 64 00 65 00 72 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 43 00 6f 00 6d 00 6d 00 65 00 6e 00 74 00 2e 00 68 00 74 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "E:\\Virus\\borra" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AW_2147601659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!AW"
        threat_id = "2147601659"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "c:\\program files\\microsoft visual studio\\vb98\\vb6.olb" ascii //weight: 20
        $x_6_2 = {c7 85 74 ff ff ff ?? ?? 40 00 c7 85 64 ff ff ff ?? ?? 40 00 ff d7 50 8d 55 b0 8d 85 5c ff ff ff 52 8d 4d 8c 50 51 ff d7 8d 95 7c ff ff ff 50 52 ff 15 ?? 10 40 00 50 ff 15 ?? 10 40 00 66 85 c0 74 59}  //weight: 6, accuracy: Low
        $x_7_3 = "@*\\AE:\\tinhoc\\V_Basic\\Virus\\V1.1\\System.vbp" wide //weight: 7
        $x_2_4 = "Recycled\\INFO.exe" wide //weight: 2
        $x_1_5 = "taskkill /f /im" wide //weight: 1
        $x_1_6 = ":\\Recycled\\Run." wide //weight: 1
        $x_1_7 = "Explorer\\Advanced\\Folder\\SuperHidden" wide //weight: 1
        $x_1_8 = "Explorer\\Advanced\\Folder\\HideFileExt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_6_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_6_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_7_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_7_*) and 1 of ($x_2_*))) or
            ((1 of ($x_20_*) and 1 of ($x_7_*) and 1 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_AX_2147602305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!AX"
        threat_id = "2147602305"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[autorun]" ascii //weight: 1
        $x_1_2 = "autorun.inf" ascii //weight: 1
        $x_1_3 = "shell\\Open\\command=" ascii //weight: 1
        $x_2_4 = {43 61 62 69 6e 65 74 57 43 6c 61 73 73 [0-16] 4d 79 20 43 6f 6d 70 75 74 65 72}  //weight: 2, accuracy: Low
        $x_5_5 = {83 f8 04 74 16 83 f8 06 74 11 83 f8 02 74 0c 83 f8 05 74 07 83 f8 00 74 02}  //weight: 5, accuracy: High
        $x_8_6 = {83 f8 02 74 1a 83 f8 04 74 15 83 f8 06 74 10 83 3d ?? ?? ?? ?? 00 74 05 83 f8 03 74 02 40 00 [0-16] c6 05 ?? ?? ?? ?? 62 fe 05 ?? ?? ?? ?? 80 3d ?? ?? ?? ?? 7b}  //weight: 8, accuracy: Low
        $x_6_7 = {89 c3 83 c3 12 80 3b 7a 0f 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*))) or
            ((1 of ($x_8_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_AY_2147602314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!AY"
        threat_id = "2147602314"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cscript c:\\Progra~1\\Intern~1\\PLUGINS\\shell~1\\down.vbs" ascii //weight: 1
        $x_1_2 = {f7 d8 1b c0 f7 d8 23 f0 f7 de 1b f6 f7 de 8b 45 d8 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? f7 d8 1b c0 f7 d8 23 f0 85 f6 75 50 c7 45 fc 0a 00 00 00 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AZ_2147602315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!AZ"
        threat_id = "2147602315"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%sAutoRun.inf" ascii //weight: 1
        $x_1_2 = "autorun.inf" wide //weight: 1
        $x_10_3 = {83 f8 02 0f 85 ?? ?? 00 00 68 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 83 c4 08 85 c0 0f 85 ?? ?? 00 00 68 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 83 c4 08 85 c0 0f 85}  //weight: 10, accuracy: Low
        $x_10_4 = {83 f8 02 0f 85 ?? ?? 00 00 8b 3d ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 ff d7 83 c4 08 85 c0 0f 85 ?? ?? 00 00 68 ?? ?? ?? ?? 56 ff d7 83 c4 08 85 c0 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_OF_2147602396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.OF"
        threat_id = "2147602396"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\autorun.inf" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_1_3 = "open=Long.exe" wide //weight: 1
        $x_1_4 = "Shellexecute=Long.exe" wide //weight: 1
        $x_1_5 = "shell\\Auto\\command=Long.exe" wide //weight: 1
        $x_1_6 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_BA_2147602411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!BA"
        threat_id = "2147602411"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "microsoft visual c++ runtime library" ascii //weight: 10
        $x_10_2 = {74 12 8a 50 01 3a 51 01 75 0e 83 c0 02 83 c1 02 84 d2 75 e4 33 c0 eb 05 1b c0 83 d8 ff 85 c0 0f 85 b8 00 00 00 53 55 57 8d 54 24 14 52 56 ff 15}  //weight: 10, accuracy: High
        $x_1_3 = "shell\\open\\Command=pics.exe" ascii //weight: 1
        $x_1_4 = "shell\\explore\\Command=downloads.exe" ascii //weight: 1
        $x_1_5 = "shell\\explore\\Command=fun.exe" ascii //weight: 1
        $x_1_6 = "shell\\explore\\Command=documents.exe" ascii //weight: 1
        $x_1_7 = "%c:\\killvbs.vbs" ascii //weight: 1
        $x_1_8 = "gods must be cr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_BJ_2147602421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!BJ"
        threat_id = "2147602421"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[autorun]" wide //weight: 1
        $x_1_2 = "shell\\open\\Command=" wide //weight: 1
        $x_1_3 = "shell\\open\\Default=1" wide //weight: 1
        $x_1_4 = ",iask.com,iask.cn,google.com,google.cn,baidu.com" wide //weight: 1
        $x_1_5 = {63 00 3a 00 5c 00 72 00 65 00 63 00 69 00 63 00 6c 00 61 00 6a 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_Win32_Autorun_BB_2147602422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!BB"
        threat_id = "2147602422"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[autorun]" wide //weight: 1
        $x_1_2 = "shell\\open\\Command=PPstream.exe" wide //weight: 1
        $x_1_3 = "shell\\open\\Default=1" wide //weight: 1
        $x_1_4 = "c:\\windows\\Seacon.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_BC_2147602423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!BC"
        threat_id = "2147602423"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[autorun]" wide //weight: 1
        $x_1_2 = "shell\\Auto\\command=Song.exe" wide //weight: 1
        $x_1_3 = "Shellexecute=Song.exe" wide //weight: 1
        $x_1_4 = "\\system32\\secpol.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_BD_2147602424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!BD"
        threat_id = "2147602424"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[autorun]" wide //weight: 1
        $x_1_2 = "Shell\\open\\command = AVSEQ011.exe" wide //weight: 1
        $x_1_3 = "Shell\\explore\\command = AVSEQ011.exe -e" wide //weight: 1
        $x_1_4 = "Shell\\open=Scan all virus" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_BE_2147602425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!BE"
        threat_id = "2147602425"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[autorun]" wide //weight: 1
        $x_1_2 = "shell\\open\\command=kavsrv.exe" wide //weight: 1
        $x_1_3 = {73 00 68 00 65 00 6c 00 6c 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 3d 00 44 00 58 00 47 00 44 00 49 00 41 00 4c 00 4f 00 47 00 2e 00 45 00 58 00 45 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "DriveType" wide //weight: 1
        $x_1_5 = "SubFolders" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_Win32_Autorun_BF_2147602426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!BF"
        threat_id = "2147602426"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[autorun]" wide //weight: 1
        $x_1_2 = "shell\\Open\\command=KDWin.exe" wide //weight: 1
        $x_1_3 = "\\KDWIN\\KDWin.vbp" wide //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_BI_2147602427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!BI"
        threat_id = "2147602427"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[autorun]" ascii //weight: 1
        $x_1_2 = "shell\\Auto\\command=scanner.exe" ascii //weight: 1
        $x_1_3 = "regedit -s C:\\windows\\system32\\1.reg" wide //weight: 1
        $x_1_4 = "autorun.inf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_BK_2147602524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!BK"
        threat_id = "2147602524"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[autorun]" wide //weight: 1
        $x_1_2 = "shell\\open\\Command=svchost.exe" wide //weight: 1
        $x_1_3 = "shell\\explore\\Command=svchost.exe" wide //weight: 1
        $x_1_4 = {00 00 44 00 72 00 69 00 76 00 65 00 73 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_BL_2147602568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!BL"
        threat_id = "2147602568"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "microsoft visual c++ runtime library" ascii //weight: 15
        $x_15_2 = {b1 68 a9 00 01 00 00 74 02 b1 69 a9 00 02 00 00 74 02 b1 6a a9 00 04 00 00 74 02 b1 6b a9 00 08 00 00 74 02 b1 6c a9 00 10 00 00 b0 6d 75 02 8a c1 59 c3}  //weight: 15, accuracy: High
        $x_4_3 = {0f be d3 89 54 24 14 e8 fb cd ff ff 8a d8 88 5c 24 13 3a 5c 24 12 74 06 88 5c 24 12 eb 0b 83 7c 24 1c 00 0f 85 e9 00 00 00 8b 44 24 14 50 8d 8c 24 34 01 00 00 68}  //weight: 4, accuracy: High
        $x_1_4 = "shell\\explore\\Command=fun.exe" ascii //weight: 1
        $x_1_5 = "%c:\\killvbs.vbs" ascii //weight: 1
        $x_1_6 = "%c:\\ntde1ect.com" ascii //weight: 1
        $x_1_7 = "%c:\\,.exe" ascii //weight: 1
        $x_1_8 = "%c:\\bit@uom.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_15_*) and 2 of ($x_1_*))) or
            ((2 of ($x_15_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_BM_2147602780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!BM"
        threat_id = "2147602780"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 10
        $x_10_2 = {0f 85 20 01 00 00 68 c0 d4 01 00 e8 ?? ?? ff ff 8d 45 e4 e8 11 00 74 15 a1 ?? ?? 14 13 ba ?? ?? 14 13 e8 ?? ?? ff ff}  //weight: 10, accuracy: Low
        $x_5_3 = {43 3a 5c 50 52 4f 47 52 41 7e 31 5c 70 72 6f 02 00 2e 65 78 65}  //weight: 5, accuracy: Low
        $x_1_4 = {68 74 74 70 3a 2f 2f [0-24] 2f 31 02 00 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = "e:\\Hide.exe" ascii //weight: 1
        $x_1_6 = "e:\\autorun.inf" ascii //weight: 1
        $x_1_7 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 77 6e 69 70 73 76 [0-1] 72 2e 65 78 65 20 2d 64 6f 77 6e}  //weight: 1, accuracy: Low
        $x_1_8 = "perefic.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_BN_2147602874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!BN"
        threat_id = "2147602874"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4b ff ff 00 20 1b (2e|44) 00 43 74 ff 04 74 ff 1b (44|45) 00 43 78 ff 04 78 ff 10 00 07 1c 00 32 04 00 78 ff 74 ff 00 00 13 00}  //weight: 10, accuracy: Low
        $x_10_2 = {3a 44 ff 2f 00 4e 34 ff 04 34 ff 0b 10 00 04 00 23 70 ff 1b 30 00 2a 23 64 ff 08 08 00 06 34 00 24 15 00 0d 48 00 16 00 6b 76 ff f4 00 c6 32 04 00 70 ff 64 ff 35 34 ff 1c f7 01 00 33 1b}  //weight: 10, accuracy: High
        $x_1_3 = "C:\\Documents and Settings\\Administrator\\Desktop\\01\\FullHouse01.vbp" wide //weight: 1
        $x_1_4 = "C:\\Full House\\FullHouse.jpg" wide //weight: 1
        $x_1_5 = "\\Kaspersky Lab" wide //weight: 1
        $x_1_6 = "InfectDrives" ascii //weight: 1
        $x_1_7 = "InfectUSB" ascii //weight: 1
        $x_1_8 = "[AUTORUN]" wide //weight: 1
        $x_1_9 = "Shell\\Open\\Command=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_BO_2147602948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!BO"
        threat_id = "2147602948"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "MSVBVM60.DLL" ascii //weight: 5
        $x_5_2 = {ff 50 04 8b 4e 78 8b 3d 10 12 40 00 ba 9c 36 72 00 ff d7 8b 4e 78 ba bc 36 72 00 83 c1 04 ff d7 8b 4e 78 ba dc 36 72 00 83 c1 08 ff d7 8b 4e 78}  //weight: 5, accuracy: High
        $x_1_3 = "*\\AD:\\Documents and Settings\\Administrador\\Mis documentos\\Mis archivos\\TODO DE VISUAL STUDIO 6.0\\Libre Salvado\\Freedom.vbp" wide //weight: 1
        $x_1_4 = {53 4d 53 53 20 20 2d 20 5b 20 4c 69 62 72 65 20 41 2e 5a 2e 56 2e 20 56 65 72 73 69 6f 6e 20 20 30 2e 02 00 20 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_AY_2147603025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AY"
        threat_id = "2147603025"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sc config schedule start= auto" wide //weight: 1
        $x_1_2 = "sc config DNSSystem type= interact type= own" wide //weight: 1
        $x_1_3 = "sc description DNSSystem \"(C) Microsoft Corporation" wide //weight: 1
        $x_1_4 = "%SystemRoot%\\system32\\SuCH0ST.exe" wide //weight: 1
        $x_1_5 = "echo o auto555.3322.org" wide //weight: 1
        $x_1_6 = "ping 127.0.0.1 -n 3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_OH_2147603410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.OH"
        threat_id = "2147603410"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\Run" ascii //weight: 1
        $x_1_2 = {5b 41 75 74 6f 52 75 6e 5d [0-32] 4f 50 45 4e 3d 54 68 75 6d 62 73 2e 65 78 65 [0-32] 73 68 65 6c 6c 65 78 65 63 75 74 65 3d 54 68 75 6d 62 73 2e 65 78 65 [0-32] 73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d 54 68 75 6d 62 73 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "\\autorun.inf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_BK_2147603428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.BK"
        threat_id = "2147603428"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "attrib +h rundll.exe" ascii //weight: 10
        $x_1_2 = "open=rundll.exe" ascii //weight: 1
        $x_1_3 = "ACTION = Carpetas" ascii //weight: 1
        $x_1_4 = "shell%copen%ccommand=rundll.exe" ascii //weight: 1
        $x_1_5 = "attrib +h %c:%cautorun.inf" ascii //weight: 1
        $x_1_6 = "C:%cWINDOWS%csystem32%ctaskkill.exe" ascii //weight: 1
        $x_1_7 = "C:%cWINDOWS%cpchealth%chelpctr%cbinaries%cmsconfig.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_E_2147604693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.E"
        threat_id = "2147604693"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "70"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Hook.dll" ascii //weight: 10
        $x_10_2 = "DllCanUnloadNow" ascii //weight: 10
        $x_10_3 = "DllRegisterServer" ascii //weight: 10
        $x_10_4 = "MsgHookOff" ascii //weight: 10
        $x_10_5 = "MsgHookOn" ascii //weight: 10
        $x_10_6 = "Microsoft Corporation Windows DLL" wide //weight: 10
        $x_10_7 = {50 50 c6 40 fb e9 83 68 fc 06 2b 40 03 51 b9 ?? ?? ?? ?? 81 34 08 ?? ?? ?? ?? e2 f7 59 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_BP_2147604759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.BP"
        threat_id = "2147604759"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "*\\AD:\\Documents\\Documents11\\Secret\\Basic\\Update\\Worm+Trojan\\worm.vbp" wide //weight: 2
        $x_1_2 = "/hav_online/files/task.rar" wide //weight: 1
        $x_1_3 = "Shellexecute=Secret.exe" wide //weight: 1
        $x_1_4 = "kdcoms.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_BQ_2147604936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.BQ"
        threat_id = "2147604936"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RajaDiraja" ascii //weight: 1
        $x_1_2 = "MainModule" ascii //weight: 1
        $x_1_3 = "Pasukan" ascii //weight: 1
        $x_1_4 = "GetSystemDirectoryA" ascii //weight: 1
        $x_1_5 = "ShellExecuteA" ascii //weight: 1
        $x_1_6 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_7 = "@*\\AD:\\Btend\\PASUKAN\\Pasukan.vbp" wide //weight: 1
        $x_1_8 = "NotStartX" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_BS_2147604996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.BS"
        threat_id = "2147604996"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "servet.exe" ascii //weight: 10
        $x_10_2 = "drivers/klick.sys" ascii //weight: 10
        $x_10_3 = "ZwUnmapViewOfSection" ascii //weight: 10
        $x_1_4 = "\\C$\\AutoExec.bat" ascii //weight: 1
        $x_1_5 = "if exist \"" ascii //weight: 1
        $x_1_6 = " goto try" ascii //weight: 1
        $x_1_7 = "Deleteme.bat" ascii //weight: 1
        $x_1_8 = "batser.bat" ascii //weight: 1
        $x_1_9 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_BR_2147605002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.BR"
        threat_id = "2147605002"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "317"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_100_2 = "UrlDownloadToFileA" ascii //weight: 100
        $x_10_3 = {68 74 74 70 3a 2f 2f [0-48] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_1_4 = "\\C$\\Setup.exe" ascii //weight: 1
        $x_1_5 = "\\C$\\AutoExec.bat" ascii //weight: 1
        $x_1_6 = "\\AutoRun.inf" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" ascii //weight: 1
        $x_1_8 = "NoDriveTypeAutoRun" ascii //weight: 1
        $x_1_9 = "[AutoRun]" ascii //weight: 1
        $x_1_10 = "open=" ascii //weight: 1
        $x_100_11 = {33 c9 51 51 51 51 51 51 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 6a 00 6a 00 8d 45 fc e8 ?? ?? ?? ?? 8d 45 fc 50 8d 45 f4 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f4 8d 55 f8 e8 ?? ?? ?? ?? 8b 55 f8 58 e8 ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 85 c0 75 3e 6a 01 8d 45 f0}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_BP_2147605055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!BP"
        threat_id = "2147605055"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shell\\infected\\command=protector.exe" ascii //weight: 1
        $x_1_2 = "\\autorun.inf" ascii //weight: 1
        $x_1_3 = "\\Local Settings\\Application Data\\Microsoft\\CD Burning\\protector.exe" ascii //weight: 1
        $x_1_4 = "wazaaapldsfsdf" ascii //weight: 1
        $x_1_5 = "Doomsday Has Come..." ascii //weight: 1
        $x_1_6 = "YOU ARE iNFECTED BY RAVO_5002" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Worm_Win32_Autorun_BT_2147605068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.BT"
        threat_id = "2147605068"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "malegebazideq" ascii //weight: 1
        $x_1_2 = "wocaonilaomuq" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_4 = {4d 73 67 48 6f 6f 6b 69 66 00 00 00 4d 73 67 48 6f 6f 6b 4f 70}  //weight: 1, accuracy: High
        $x_1_5 = {57 69 6e 53 79 73 ?? ?? 2e 54 61 6f}  //weight: 1, accuracy: Low
        $x_1_6 = {57 69 6e 53 79 73 ?? ?? 2e 53 79 73}  //weight: 1, accuracy: Low
        $x_1_7 = "shellexecute=AutoRun.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Worm_Win32_Autorun_BT_2147605069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.BT"
        threat_id = "2147605069"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "malegebazideq" ascii //weight: 1
        $x_1_2 = "wocaonilaomuq" ascii //weight: 1
        $x_1_3 = {20 2f 53 54 41 52 54 00 ff ff ff ff 07 00 00 00 20 51 51 55 49 4e 3a 00 ff ff ff ff}  //weight: 1, accuracy: High
        $x_1_4 = "Tencent_QQToolBar" ascii //weight: 1
        $x_1_5 = {20 51 51 50 53 57 3a 00 ff ff ff ff 09 00 00 00 20 2f 53 54 41 54 3a 31 30 00}  //weight: 1, accuracy: High
        $x_1_6 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 1
        $x_1_7 = {4e 75 6d 62 65 72 3d 00 ff ff ff ff 0a 00 00 00 26 50 61 73 73 57 6f 72 64 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Worm_Win32_Autorun_OI_2147605409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.OI"
        threat_id = "2147605409"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 25 73 0d 0a 00 00 00 6f 70 65 6e 3d 25 73 0d 0a 00 00 00 5b 41 75 74 6f 52 75 6e 5d 0d 0a 00 77 2b 00 00 25 63 3a 5c 41 75 74 6f 52 75 6e 2e 69 6e 66 00 25 63 3a 5c 25 73}  //weight: 1, accuracy: High
        $x_1_2 = {63 3a 5c 70 61 67 65 66 69 6c 65 2e 70 69 66 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00 00 53 68 65 6c 6c 45 78 65 63 75 74 65 41}  //weight: 1, accuracy: High
        $x_1_3 = {66 75 63 6b 77 65 62 00 2f 2a 28 26 2a 5e 54 47 48 2a 4a 49 48 47 5e 26 2a 28 26 5e 25 2a 28 2a 29 4f 4b 29 28 2a 26 5e 25 24 45 44 52 47 46 25 26 5e 2e 68 74 6d 6c 00 47 45 54 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_OK_2147605422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.OK"
        threat_id = "2147605422"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 41 75 74 6f 52 75 6e 5d 0d 0a 6f 70 65 6e 3d 53 65 74 75 70 2e 65 78 65 0d 0a 73 68 65 6c 6c 65 78 65 63 75 74 65 3d 53 65 74 75 70 2e 65 78 65 0d 0a 73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d 53 65 74 75 70 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 53 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 52 75 6e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 53 79 73 52 65 42 75 69 6c 64 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {52 61 62 62 69 74 31 39 37 35 5f 30 33 5f 32 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 52 61 62 62 69 74 5f 31 39 37 35 30 33 32 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_CM_2147605591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.CM"
        threat_id = "2147605591"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {eb 10 66 62 3a 43 2b 2b 48 4f 4f 4b 90 e9}  //weight: 20, accuracy: High
        $x_10_2 = "geocities.com/gameslink/" ascii //weight: 10
        $x_10_3 = "\\System\\svchost.exe" ascii //weight: 10
        $x_10_4 = {00 75 70 64 61 74 65 2e 65 78 65 00 61 75 74 6f 72 75 6e 2e 69 6e 66 00}  //weight: 10, accuracy: High
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_BO_2147605830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.BO"
        threat_id = "2147605830"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5b 61 75 74 6f 72 75 6e 5d [0-16] 61 75 74 6f 72 75 6e 2e 69 6e 66 [0-16] 61 75 74 6f 72 75 6e 2e 65 78 65 [0-16] 5c 5c 3f 5c 25 63 3a}  //weight: 10, accuracy: Low
        $x_10_2 = {73 79 73 64 65 62 2e 69 6e 69 00 00 5c 64 65 62 75 67 5c 00 6d 73 6d 73 67 73 2e 65 78 65}  //weight: 10, accuracy: High
        $x_10_3 = {48 4f 53 54 00 00 00 00 55 53 42 44 52 49 56 45 52 00}  //weight: 10, accuracy: High
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "Windows Messenger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_OM_2147606085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.OM"
        threat_id = "2147606085"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%c:\\Autorun.inf" ascii //weight: 1
        $x_1_2 = {5b 41 75 74 6f 52 75 6e 5d 0d 0a 53 68 65 6c 6c 45 78 65 63 75 74 65 3d 25 73}  //weight: 1, accuracy: High
        $x_1_3 = "%temp%\\autorun.dat" ascii //weight: 1
        $x_1_4 = {4e 6f 44 72 69 76 65 54 79 70 65 41 75 74 6f 52 75 6e 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72}  //weight: 1, accuracy: High
        $x_1_5 = "ShowSuperHidden" ascii //weight: 1
        $x_6_6 = {57 69 6e 64 6f 77 73 55 70 64 61 74 65 72 00 00 57 69 6e 55 70 64 74 65 72 2e 65 78 65}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_CA_2147606503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.CA"
        threat_id = "2147606503"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CurrentVersion\\Image File Execution Options\\procexp.exe\\Debugger" wide //weight: 1
        $x_1_2 = "\\~A~m~B~u~R~a~D~u~L~\\msvbvm60.dll" wide //weight: 1
        $x_1_3 = "KillAntivirus" ascii //weight: 1
        $x_1_4 = "Shellexecute=MyImages.exe" wide //weight: 1
        $x_1_5 = "taskkill /f /im explorer.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_Win32_Autorun_ON_2147606598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ON"
        threat_id = "2147606598"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {56 42 41 36 2e 44 4c 4c 00}  //weight: 10, accuracy: High
        $x_10_2 = "\\virus\\Project1.vbp" wide //weight: 10
        $x_1_3 = "fatalsystemerror.narod.ru" wide //weight: 1
        $x_1_4 = "vir.htm" wide //weight: 1
        $x_1_5 = "teen_movie.exe" wide //weight: 1
        $x_1_6 = "OPEN=teen_movie.exe" wide //weight: 1
        $x_10_7 = "RasEnumConnectionsA" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_OP_2147606988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.OP"
        threat_id = "2147606988"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 00 5c 00 6d 00 73 00 61 00 72 00 74 00 69 00 2e 00 63 00 6f 00 6d 00 00 00}  //weight: 5, accuracy: High
        $x_4_2 = "\\LocalS~1\\Applic~1\\Micros~1\\CDBurn~1\\auto.exe" wide //weight: 4
        $x_4_3 = "F:\\Research\\mydoc666\\LATEST\\folder_x\\File Folder.vbp" wide //weight: 4
        $x_2_4 = "\"%1\" %*" wide //weight: 2
        $x_1_5 = "\\smss.exe" wide //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_1_7 = "inifile\\shell\\open\\command" wide //weight: 1
        $x_1_8 = "shell\\open\\Default=1" wide //weight: 1
        $x_1_9 = "shell\\explore\\Command=auto.exe" wide //weight: 1
        $x_1_10 = "\\NetHood\\*.*" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 6 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_OQ_2147606990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.OQ"
        threat_id = "2147606990"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {43 57 6f 72 6d 42 65 67 69 6e 00 00 6e 65 74 2e 65 78 65 00 61 75 74 6f 72 75 6e 2e 69 6e 66 00 73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d 6e 65 74 2e 65 78 65}  //weight: 10, accuracy: High
        $x_10_2 = "<iframe src=http://%77%77%77%2E%6B%61%6E%67%6B%2E%63%6E/%61%32%2E%68%74%6D width=0 height=0></iframe>" ascii //weight: 10
        $x_1_3 = "4D36E967-E325-11CE-BFC1-08002BE10318" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_OR_2147607526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.OR"
        threat_id = "2147607526"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Documents and Settings\\MS WINDOWS\\Desktop\\Final Valga\\svchots.vbp" wide //weight: 2
        $x_1_2 = "em.{645FF040-5081-101B-9F08-00AA002F954E}" wide //weight: 1
        $x_1_3 = "shell\\open\\Command=open" wide //weight: 1
        $x_1_4 = "[AutoRun]" wide //weight: 1
        $x_1_5 = {66 72 6d 56 61 6c 67 61 00 0d 01 0a 00 54 61 73 6b 4b 69 6c 6c 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_XFO_2147607555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.XFO"
        threat_id = "2147607555"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 78 00 6c 00 73 00 [0-255] 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 [0-255] 41 00 55 00 54 00 4f 00 52 00 55 00 4e 00 2e 00 49 00 4e 00 46 00 [0-16] 5b 00 41 00 75 00 74 00 6f 00 52 00 75 00 6e 00 5d 00 [0-16] 6f 00 70 00 65 00 6e 00 3d 00 [0-16] 73 00 68 00 65 00 6c 00 6c 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 3d 00 [0-16] 73 00 68 00 65 00 6c 00 6c 00 5c 00 41 00 75 00 74 00 6f 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 [0-16] 73 00 68 00 65 00 6c 00 6c 00 3d 00 41 00 75 00 74 00 6f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_OS_2147607605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.OS"
        threat_id = "2147607605"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {43 80 fb 5b 0f 85 b2 f4 ff ff b3 43}  //weight: 5, accuracy: High
        $x_5_2 = "GetDriveTypeA" ascii //weight: 5
        $x_5_3 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c 00}  //weight: 5, accuracy: High
        $x_1_4 = "\\help\\CSRSS.exe" ascii //weight: 1
        $x_1_5 = "\\help\\Autorun.inf" ascii //weight: 1
        $x_1_6 = "\\security\\CSRSS.exe" ascii //weight: 1
        $x_1_7 = "\\security\\Autorun.inf" ascii //weight: 1
        $x_1_8 = "open=CSRSS.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_CC_2147607880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.CC"
        threat_id = "2147607880"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "shell\\Auto\\command=Execl.exe" ascii //weight: 3
        $x_3_2 = "shellexecute=Execl.exe" ascii //weight: 3
        $x_3_3 = "open=Execl.exe" ascii //weight: 3
        $x_3_4 = "[AutoRun]" ascii //weight: 3
        $x_3_5 = "\\autorun.inf" ascii //weight: 3
        $x_5_6 = "StartServiceCtrlDispatcherA" ascii //weight: 5
        $x_5_7 = "CreateThread" ascii //weight: 5
        $x_5_8 = "WinExec" ascii //weight: 5
        $x_5_9 = "GetDriveTypeA" ascii //weight: 5
        $x_1_10 = "TXOService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 5 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_CD_2147607989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.CD"
        threat_id = "2147607989"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6d 79 6c 6f 76 65 00 32 4e 00 00 50 72 6f 6a 65 63 74 31 00 06 00 00 00 b4 32 40 00}  //weight: 5, accuracy: High
        $x_5_2 = "MSVBVM60.DLL" ascii //weight: 5
        $x_1_3 = "GetLogicalDriveStringsA" ascii //weight: 1
        $x_1_4 = "GetDriveTypeA" ascii //weight: 1
        $x_1_5 = "IMClass" wide //weight: 1
        $x_1_6 = "GetNameSpace" wide //weight: 1
        $x_1_7 = "AddressEntries" wide //weight: 1
        $x_1_8 = "CreateItem" wide //weight: 1
        $x_1_9 = "Subject" wide //weight: 1
        $x_1_10 = "Attachments" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_CI_2147608505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.CI"
        threat_id = "2147608505"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "432"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "\\SERVICES.EXE" ascii //weight: 100
        $x_100_2 = "regedit.exe /s %s" ascii //weight: 100
        $x_100_3 = "%temp%\\msdtr.exe" ascii //weight: 100
        $x_100_4 = "MSN Explorer Signup" ascii //weight: 100
        $x_10_5 = "InternetReadFile" ascii //weight: 10
        $x_10_6 = "cmd /c net user >>" ascii //weight: 10
        $x_10_7 = "CAN'T FIND MICROSOFT" ascii //weight: 10
        $x_1_8 = "ShowSuperHidden" ascii //weight: 1
        $x_1_9 = "%c:\\*.*" ascii //weight: 1
        $x_1_10 = "%s\\explore.exe" ascii //weight: 1
        $x_1_11 = "%s\\Recycled\\explore.exe" ascii //weight: 1
        $x_1_12 = "%s\\AutoRun.inf" ascii //weight: 1
        $x_1_13 = "%c:\\AutoRun.inf" ascii //weight: 1
        $x_1_14 = "CLSID={645FF040-5081-101B-9F08-00AA002F954E}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_CJ_2147608509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.CJ"
        threat_id = "2147608509"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Documents and Settings\\TASDA.TASDA-B20F43BAE\\Desktop\\007\\Project1.vbp" wide //weight: 10
        $x_5_2 = "C:\\WINDOWS\\system32\\dllcache\\Recycler.{645FF040-5081-101B-9F08-00AA002F954E}\\svchost.exe" wide //weight: 5
        $x_5_3 = "C:\\WINDOWS\\system32\\dllcache\\Recycler.{645FF040-5081-101B-9F08-00AA002F954E}\\Global.exe" wide //weight: 5
        $x_5_4 = "Explorer\\Advanced\\Folder\\SuperHidden" wide //weight: 5
        $x_1_5 = "[autorun]" wide //weight: 1
        $x_1_6 = "Shellexecute=MS-DOS.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_CR_2147608710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.CR"
        threat_id = "2147608710"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "422"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "MSVBVM60.DLL" ascii //weight: 100
        $x_100_2 = "*ActiveMSNP*" wide //weight: 100
        $x_100_3 = "\\Pablo\\Documentos\\Visual\\proyectos\\LiveUpdatee.vbp" wide //weight: 100
        $x_100_4 = "http://usuarios.lycos.es/svcpage" wide //weight: 100
        $x_10_5 = "AutoRun.inf" wide //weight: 10
        $x_10_6 = "[AutoRun]" wide //weight: 10
        $x_1_7 = "/updt.exe" wide //weight: 1
        $x_1_8 = "C:\\WINDOWS\\SYSTEM\\bsu.dat" wide //weight: 1
        $x_1_9 = "C:\\Windows\\inf\\infdata.inf" wide //weight: 1
        $x_1_10 = "C:/windows/system/servidor.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_CS_2147609010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.CS"
        threat_id = "2147609010"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[fuking operating systems]" wide //weight: 10
        $x_10_2 = "Select * from Win32_Process" wide //weight: 10
        $x_1_3 = "boot.ini" wide //weight: 1
        $x_1_4 = "[autorun]" wide //weight: 1
        $x_1_5 = "[boot loader]" wide //weight: 1
        $x_1_6 = "shellexecute=.\\" wide //weight: 1
        $x_1_7 = "shell\\1\\=Open" wide //weight: 1
        $x_1_8 = "taskmgr.exe" wide //weight: 1
        $x_1_9 = "regedit.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_CU_2147609058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.CU"
        threat_id = "2147609058"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "start WORNING.txt" ascii //weight: 10
        $x_10_2 = "title YOU ARE DEAD" ascii //weight: 10
        $x_1_3 = "net stop sharedaccess >nul" ascii //weight: 1
        $x_1_4 = "copy %0 %windir%\\system32\\cmd.bat" ascii //weight: 1
        $x_1_5 = "%s% /im av* /f >nul" ascii //weight: 1
        $x_1_6 = "%s% /im anti* /f >nul" ascii //weight: 1
        $x_1_7 = "%s% /im spy* /f >nul" ascii //weight: 1
        $x_1_8 = "for %%a in (c %alldrive%) do del %%a:\\" ascii //weight: 1
        $x_1_9 = "net user administrator 123456 >nul" ascii //weight: 1
        $x_1_10 = "for %%c in (c %alldrive%) do del %%c:\\*.gho /f /s /q >nul" ascii //weight: 1
        $x_1_11 = "echo [windows] >> %windir%\\win.ini" ascii //weight: 1
        $x_1_12 = "echo [boot] >> %windir%\\system.ini" ascii //weight: 1
        $x_1_13 = "copy %0 %systemroot%\\windows.bat >nul" ascii //weight: 1
        $x_1_14 = "copy %0 %windir%\\system32\\logon.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_OT_2147609072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!OT"
        threat_id = "2147609072"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[autorun]" wide //weight: 1
        $x_1_2 = {6f 00 70 00 65 00 6e 00 3d 00 44 00 72 00 69 00 76 00 65 00 2e 00 64 00 72 00 76 00 2e 00 6c 00 6e 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "shell\\Auto\\command=Drive.drv.lnk" wide //weight: 1
        $x_1_4 = {00 00 4e 00 6f 00 44 00 72 00 69 00 76 00 65 00 73 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_OT_2147609110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.OT"
        threat_id = "2147609110"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 53 74 61 72 74 45 78 70 6c 6f 72 65 72 00 00 25 73 5c 62 6c 75 65 66 69 72 65 2e 65 78 65 00 65 78 70 6c 6f 72 65 72 20 25 73}  //weight: 1, accuracy: High
        $x_1_2 = {25 73 5c 73 76 63 68 6f 76 73 74 2e 45 58 45 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e}  //weight: 1, accuracy: High
        $x_1_3 = "shell\\Auto\\command=\"svchovst.EXE\"" ascii //weight: 1
        $x_1_4 = "[AUTORUN]" ascii //weight: 1
        $x_1_5 = "%sautorun.inf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_OU_2147609112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.OU"
        threat_id = "2147609112"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%SystemRoot%\\System32\\Windows.exe" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_3 = "shell\\open\\Command=regsvr32.exe /s" ascii //weight: 1
        $x_1_4 = "[AutoRun]" ascii //weight: 1
        $x_1_5 = {43 4c 53 49 44 3d 7b 36 34 35 46 46 30 34 30 2d 35 30 38 31 2d 31 30 31 42 2d 39 46 30 38 2d 30 30 41 41 30 30 32 46 39 35 34 45 7d [0-16] 3a 5c 52 65 63 79 63 6c 65 64 5c 41 75 74 6f 52 75 6e 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_OV_2147609147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.OV"
        threat_id = "2147609147"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\" wide //weight: 1
        $x_1_2 = "ShowSuperHidden" wide //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
        $x_5_4 = {5b 00 41 00 75 00 74 00 6f 00 52 00 75 00 6e 00 5d 00 00 02 6f 00 70 00 65 00 6e 00 3d 00 [0-48] 2e 00 65 00 78 00 65 00 00 02 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 [0-48] 2e 00 65 00 78 00 65 00 00 02 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 3d 00 31 00 00 02 73 00 68 00 65 00 6c 00 6c 00 5c 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 5c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 [0-48] 2e 00 65 00 78 00 65 00}  //weight: 5, accuracy: Low
        $x_1_5 = {6a 04 52 6a 04 6a 00 8d 45 ?? 68 ?? ?? ?? ?? 50 c7 45 cc 00 00 00 00 ff d7 8b 4d ?? 50 51 e8 ?? ?? ff ff ff d6 8d 4d ?? ff d3 8b 55 ?? 52 e8 ?? ?? ff ff ff d6 68 ?? ?? ?? ?? eb 19}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_XFP_2147609209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.XFP"
        threat_id = "2147609209"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\PROB_WINDOWS\\MYVIRUS\\MY_PROY_VIRAL\\rodri.vbp" wide //weight: 5
        $x_5_2 = ":\\WINDOWS\\system2007.exe" wide //weight: 5
        $x_5_3 = "action=Disk rodri(Te estoy espiando)" wide //weight: 5
        $x_5_4 = "shell\\install=& MATAR AL FLASH..." wide //weight: 5
        $x_1_5 = "\\system32\\driro.exe" wide //weight: 1
        $x_1_6 = "\\system32\\rodri.exe" wide //weight: 1
        $x_1_7 = "[autorun]" wide //weight: 1
        $x_1_8 = "icon=rodri.exe,0" wide //weight: 1
        $x_1_9 = "shellexecute=rodri.exe open" wide //weight: 1
        $x_1_10 = "shell\\install\\command=rodri.exe open" wide //weight: 1
        $x_1_11 = "\\ESET\\nod32.exe" wide //weight: 1
        $x_1_12 = ":\\rodrigo.jpg" wide //weight: 1
        $x_1_13 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\rodri" wide //weight: 1
        $x_1_14 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL\\CheckedValue" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 8 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_1_*))) or
            ((4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_CX_2147609270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!CX"
        threat_id = "2147609270"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Windows\\CurrentVersion\\Run\\Virus" wide //weight: 10
        $x_10_2 = {4d 00 69 00 78 00 61 00 [0-4] 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_1_3 = "shell\\open\\command = " wide //weight: 1
        $x_1_4 = "procexp*" wide //weight: 1
        $x_1_5 = "shell\\Explore\\command = " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_CY_2147609271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!CY"
        threat_id = "2147609271"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = {62 79 74 65 73 54 6f 74 61 6c 00 00 46 6e 61 6d 65 00 00 00 6d 73 45 73 70 65 72 61 00 00 00 00 69 6e 74 65 72 76 61 6c 00 00 00 00 46 69 6c 65 4e 61 6d 65 00 00 00 00 64 69 73 63 6f 00 00 00}  //weight: 10, accuracy: High
        $x_10_3 = "C:\\Archivos de programa\\Messenger\\msmsgs.exe" ascii //weight: 10
        $x_10_4 = "D:\\Sources\\VBasic\\Hugo 2.0\\Project1.vbp" wide //weight: 10
        $x_1_5 = "ModSocketMaster" ascii //weight: 1
        $x_1_6 = "Client_DataArrival" ascii //weight: 1
        $x_1_7 = "RemoteHost" ascii //weight: 1
        $x_1_8 = "sURLFileName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_CW_2147609409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.CW"
        threat_id = "2147609409"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "202"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Cache\\Special Paths\\MyPath" ascii //weight: 10
        $x_10_2 = "_FOR_BIANDOUER" ascii //weight: 10
        $x_10_3 = "GetHookProvider" ascii //weight: 10
        $x_10_4 = "LANMANNT" ascii //weight: 10
        $x_10_5 = "\\drivercashe" ascii //weight: 10
        $x_10_6 = "\\winmine.exe" ascii //weight: 10
        $x_10_7 = "mswsock2.dll" ascii //weight: 10
        $x_10_8 = "\\wsm_32" ascii //weight: 10
        $x_10_9 = "[AutoRun]" ascii //weight: 10
        $x_5_10 = {6f 70 65 6e 3d [0-16] 2e 70 69 66}  //weight: 5, accuracy: Low
        $x_5_11 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d [0-16] 2e 70 69 66}  //weight: 5, accuracy: Low
        $x_1_12 = "Netdll-" ascii //weight: 1
        $x_1_13 = "KeyBoarddll-" ascii //weight: 1
        $x_1_14 = "Screendll-" ascii //weight: 1
        $x_1_15 = "Audiodll-" ascii //weight: 1
        $x_1_16 = "Videodll-" ascii //weight: 1
        $x_1_17 = "Searchdll-" ascii //weight: 1
        $x_1_18 = "ShareInfectdll-" ascii //weight: 1
        $x_1_19 = "Module_Main_" ascii //weight: 1
        $x_100_20 = {8b 44 24 10 8d 0c 06 8b c6 99 f7 fb 8a 44 3a 04 30 01 46 3b 74 24 14 7c e7}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 9 of ($x_10_*) and 1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((1 of ($x_100_*) and 9 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_CX_2147609556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.CX!dr"
        threat_id = "2147609556"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "dr: dropper component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "331"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "[autorun]" ascii //weight: 100
        $x_100_2 = "autorun.inf" ascii //weight: 100
        $x_100_3 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_10_4 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d [0-8] 2e 64 6f 63 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_5 = {63 6f 70 79 20 2f 79 20 25 30 20 [0-16] 2e 64 6f 63 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_6 = {63 6f 70 79 20 25 30 20 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 5c [0-8] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_7 = {63 6f 70 79 20 2f 79 20 25 30 20 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 52 65 73 74 6f 72 65 5c [0-8] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_1_8 = "winoff.exe" ascii //weight: 1
        $x_1_9 = "tskill WinOff" ascii //weight: 1
        $x_1_10 = "copy /y %MYFILES%\\Autorun.inf" ascii //weight: 1
        $x_1_11 = "del \"%SystemRoot%\\System32\\Restore\" /f /a /q" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_100_*) and 4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_CX_2147609557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.CX"
        threat_id = "2147609557"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "semena_door" ascii //weight: 10
        $x_10_2 = ".bat C:\\myapp.exe" ascii //weight: 10
        $x_10_3 = "cmd.exe /c C:\\WINDOWS" ascii //weight: 10
        $x_10_4 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_5 = {2f 76 20 41 6e 74 69 76 69 72 75 7a 20 2f 64 20 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 5c [0-8] 2e 65 78 65}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_CX_2147609557_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.CX"
        threat_id = "2147609557"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "semena_door" ascii //weight: 10
        $x_10_2 = {2e 62 61 74 [0-16] 40 73 68 69 66 74}  //weight: 10, accuracy: Low
        $x_10_3 = "reg add \"hklm\\software\\microsoft\\windows\\currentversion\\run" ascii //weight: 10
        $x_10_4 = {2f 76 20 41 6e 74 69 76 69 72 75 7a 20 2f 64 20 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 5c [0-8] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_5 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_CY_2147609571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.CY"
        threat_id = "2147609571"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "73"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "dEL %0 /a" ascii //weight: 10
        $x_10_2 = "[AutoRun]" ascii //weight: 10
        $x_10_3 = "Shell\\Open=" ascii //weight: 10
        $x_10_4 = "AutoRun.inf" ascii //weight: 10
        $x_10_5 = "\\SYSTEM32\\svchost.exe" ascii //weight: 10
        $x_10_6 = "\\Device\\PhysicalMemory" wide //weight: 10
        $x_10_7 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_1_8 = "InternetReadFile" ascii //weight: 1
        $x_1_9 = "WriteProcessMemory" ascii //weight: 1
        $x_1_10 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_11 = "mylove" ascii //weight: 1
        $x_1_12 = "loveyou" ascii //weight: 1
        $x_1_13 = "baby123" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_CZ_2147609681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.CZ"
        threat_id = "2147609681"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "[AutoRun]" ascii //weight: 10
        $x_10_2 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_3 = {6f 70 65 6e 3d [0-8] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_4 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d [0-8] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_1_5 = "\\realsched.exe" wide //weight: 1
        $x_1_6 = "winmgmts:\\\\.\\root\\" wide //weight: 1
        $x_1_7 = "cmd.exe /c shutdown -s" wide //weight: 1
        $x_1_8 = "\\realsched\\TageHaider.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_DA_2147609682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.DA"
        threat_id = "2147609682"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "autorun.inf" ascii //weight: 1
        $x_1_2 = "[AutoRun]" ascii //weight: 1
        $x_1_3 = "shell\\open\\Command=lcg.exe" ascii //weight: 1
        $x_1_4 = "HKCU\\Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_5 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "http://cc.wzxqy.com/tt/mm.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_DB_2147609736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.DB"
        threat_id = "2147609736"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\WINDOWS\\SYSTEM32\\liveupdata.dll" ascii //weight: 1
        $x_1_2 = "no create" ascii //weight: 1
        $x_1_3 = "winlive.exe" ascii //weight: 1
        $x_1_4 = "autorun.inf" ascii //weight: 1
        $x_1_5 = "[AutoRun]" ascii //weight: 1
        $x_1_6 = "shell\\AutoOpen\\command=.\\MSOCache\\90000804-6000-11D3-8CFE-0150048383C0\\KB915866.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_DB_2147609736_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.DB"
        threat_id = "2147609736"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "echo [AutoRun]>>C:\\autorun.inf" ascii //weight: 2
        $x_2_2 = "IF exist C:\\autorun.inf (attrib -s -h -r C:\\autorun.inf & del /f /q /a:s E:\\autorun.inf & del /f /q /a:h E:\\autorun.inf & copy /y \"C:\\autorun.inf\" \"E:\\autorun.inf\" & attrib +s +h +r E:\\autorun.inf & attrib +s +h +r C:\\autorun.inf)" ascii //weight: 2
        $x_1_3 = "if not exist F:\\ (goto GW)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_DC_2147609769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.DC"
        threat_id = "2147609769"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "WSAStartup" ascii //weight: 10
        $x_10_2 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_3 = "\\Infeccion\\Server.vbp" wide //weight: 10
        $x_1_4 = "Zonealarm.Exe" wide //weight: 1
        $x_1_5 = "Anti-Trojan.Exe" wide //weight: 1
        $x_1_6 = "\\capture.jpg" wide //weight: 1
        $x_1_7 = "\\system32\\System32.exe" wide //weight: 1
        $x_1_8 = "\\system32\\MSWINSCK.OCX" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_DE_2147609852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.DE"
        threat_id = "2147609852"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "[AutoRun]" wide //weight: 10
        $x_10_3 = ":\\autorun.inf" wide //weight: 10
        $x_10_4 = "\\proy\\icos.vbp" wide //weight: 10
        $x_10_5 = "shellexecute = boot.vbs" wide //weight: 10
        $x_1_6 = "Set oShell=CreateObject(\"WScript.Shell\")" wide //weight: 1
        $x_1_7 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_DF_2147609869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.DF"
        threat_id = "2147609869"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "URLDownloadToFileA" ascii //weight: 10
        $x_1_3 = "autorun.inf" wide //weight: 1
        $x_1_4 = {6f 00 70 00 65 00 6e 00 3d 00 [0-8] 2e 00 70 00 69 00 66 00}  //weight: 1, accuracy: Low
        $x_1_5 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 61 00 75 00 74 00 6f 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 [0-8] 2e 00 70 00 69 00 66 00}  //weight: 1, accuracy: Low
        $x_1_6 = "net stop sharedaccess" wide //weight: 1
        $x_1_7 = "\\cmd.exe /e /t /g everyone" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_OZ_2147609910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.OZ"
        threat_id = "2147609910"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 [0-17] 5b 61 75 74 6f 72 75 6e 5d [0-17] 73 68 65 6c 6c 65 78 65 63 75 74 65 3d 52 45 43 59 43 4c 45 [0-32] 73 68 65 6c 6c 3d 73 74 61 72 74 [0-17] 73 68 65 6c 6c 5c 73 74 61 72 74 5c 63 6f 6d 6d 61 6e 64 3d 52 45 43 59 43 4c 45}  //weight: 5, accuracy: Low
        $x_1_2 = "Documents of" ascii //weight: 1
        $x_1_3 = "Music of" ascii //weight: 1
        $x_1_4 = {44 69 73 61 62 6c 65 54 61 73 6b 6d 67 72 [0-16] 44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_DH_2147609994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.DH"
        threat_id = "2147609994"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "explorerbar" wide //weight: 10
        $x_10_2 = "\\autorun.inf" wide //weight: 10
        $x_10_3 = "UnhookWindowsHookEx" ascii //weight: 10
        $x_10_4 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_5 = "Inicio\\Programas\\Inicio\\svchost.EXE" ascii //weight: 10
        $x_1_6 = "\\WKSM.EXE" wide //weight: 1
        $x_1_7 = "\\Data.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_DI_2147610140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!DI"
        threat_id = "2147610140"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[autorun]" wide //weight: 1
        $x_1_2 = "shell\\Auto\\command=rawdata.exe" wide //weight: 1
        $x_1_3 = {73 00 68 00 65 00 6c 00 6c 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 3d 00 72 00 61 00 77 00 64 00 61 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "DriveType" wide //weight: 1
        $x_1_5 = "SubFolders" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_Win32_Autorun_DI_2147610190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.DI"
        threat_id = "2147610190"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "[autorun]" wide //weight: 10
        $x_10_3 = "\\Autorun.inf" wide //weight: 10
        $x_10_4 = "open=svchost.exe" wide //weight: 10
        $x_1_5 = "label=Flash Drive" wide //weight: 1
        $x_1_6 = "\\Startup\\svchost.exe" wide //weight: 1
        $x_1_7 = "action=Run Virus Cleaner" wide //weight: 1
        $x_1_8 = "..the greatest part of your life is when you achive emptiness.." wide //weight: 1
        $x_1_9 = "So im still here..well, i have a surprise waiting for the My Documents Folder!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_DP_2147610506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.DP"
        threat_id = "2147610506"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KAVStart.exe" wide //weight: 1
        $x_1_2 = "regread" wide //weight: 1
        $x_1_3 = "cmd.exe /c net stop KWatchsvc" wide //weight: 1
        $x_1_4 = "360safe.exe" wide //weight: 1
        $x_1_5 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SounMan" wide //weight: 1
        $x_1_6 = "auto.pif" wide //weight: 1
        $x_1_7 = "Autorun.inf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_DQ_2147610516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.DQ"
        threat_id = "2147610516"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "fuck.reg" ascii //weight: 1
        $x_1_2 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 54 65 6d 70 5c [0-8] 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 54 65 6d 70 5c [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "Autorun.inf" ascii //weight: 1
        $x_1_5 = "kwatch.exe" ascii //weight: 1
        $x_1_6 = "kvsrvxp.exe" ascii //weight: 1
        $x_1_7 = "VPTray.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_DR_2147610517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.DR"
        threat_id = "2147610517"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 00 6f 00 72 00 6d 00 5c 00 [0-16] 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = "autorun.inf" wide //weight: 1
        $x_1_3 = {53 00 68 00 65 00 6c 00 6c 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 3d 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_1_5 = "userinit.exe" wide //weight: 1
        $x_1_6 = "http://" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_DV_2147610518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.DV"
        threat_id = "2147610518"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PbWzdmngmt" wide //weight: 1
        $x_1_2 = "Mourn_Operator1`1.exe" wide //weight: 1
        $x_1_3 = "shimgvw.dll" wide //weight: 1
        $x_1_4 = "jpeg" wide //weight: 1
        $x_1_5 = "\\shell\\open\\command" wide //weight: 1
        $x_1_6 = "AUTORUN.INF" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_DW_2147610527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.DW"
        threat_id = "2147610527"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 25 ?? ?? ?? ?? 00 68 ?? ?? ?? ?? 6a 04 6a 00 6a 04 6a 00 6a ff e8 ea 01 00 00 85 c0 74 ?? a3 ?? ?? ?? ?? 6a 04 6a 00 6a 00 6a 02 ff 35 ac 22 00 10 e8 f2 01 00 00 85 c0 74 ?? ff 75 08 8f 00 50 e8 fb 01 00 00 6a 00 ff 35 cc 22 00 10 68 5f 13 00 10 6a 05 e8 05 02 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "nthide.dll" ascii //weight: 1
        $x_1_3 = "HideProces" ascii //weight: 1
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "NtQuerySystemInformation" ascii //weight: 1
        $x_1_6 = "EnumWindows" ascii //weight: 1
        $x_1_7 = "Process32First" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_EA_2147610538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.EA"
        threat_id = "2147610538"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Amigda\\Amigda.vbp" wide //weight: 1
        $x_1_2 = "AutoRun.inf" wide //weight: 1
        $x_1_3 = "[AutoRun]" wide //weight: 1
        $x_1_4 = "Hidden" wide //weight: 1
        $x_1_5 = "ShowSuperHidden" wide //weight: 1
        $x_1_6 = "DisableRegistryTools" wide //weight: 1
        $x_1_7 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" wide //weight: 1
        $x_1_8 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoFolderOptions" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_EB_2147610539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.EB"
        threat_id = "2147610539"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b f6 3c 55 03 f0 ff 15 ?? ?? ?? ?? 2b c6 50 e8 5c 06 00 00 59 83 f8 1e 59}  //weight: 1, accuracy: Low
        $x_1_2 = "log.exe" ascii //weight: 1
        $x_1_3 = "\\drivers\\smcilib.sys" ascii //weight: 1
        $x_1_4 = "search.dll" ascii //weight: 1
        $x_1_5 = "QMsg.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_DZ_2147610541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.DZ"
        threat_id = "2147610541"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2bf41072-b2b1-21c1-b5c1-0305f4155515" ascii //weight: 1
        $x_1_2 = "AutoRun.inf" ascii //weight: 1
        $x_1_3 = "[AutoRun]" ascii //weight: 1
        $x_1_4 = "shell\\open\\Command" ascii //weight: 1
        $x_1_5 = "HideFileExt" ascii //weight: 1
        $x_1_6 = "ShowSuperHidden" ascii //weight: 1
        $x_1_7 = "InternetReadFile" ascii //weight: 1
        $x_1_8 = "WinExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_DX_2147610542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.DX"
        threat_id = "2147610542"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[autorun]" wide //weight: 2
        $x_2_2 = "shell\\open\\Command=Open.exe" wide //weight: 2
        $x_2_3 = "Grisoft\\Avg free\\avg" wide //weight: 2
        $x_1_4 = "NoShellSearchButton" wide //weight: 1
        $x_1_5 = "HideFileExt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_EC_2147610543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.EC"
        threat_id = "2147610543"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell\\Scan_With_AntiVirus\\command=" wide //weight: 1
        $x_1_2 = "ShowSuperHidden" wide //weight: 1
        $x_1_3 = "autorun.inf" wide //weight: 1
        $x_1_4 = "GRISOFT" wide //weight: 1
        $x_1_5 = "AntiVirus detected!" wide //weight: 1
        $x_1_6 = "kill_proc_shell" ascii //weight: 1
        $x_1_7 = "Kill_Proc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Worm_Win32_Autorun_EE_2147610585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.EE"
        threat_id = "2147610585"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "MisVh55.exe" ascii //weight: 1
        $x_1_3 = "NoRun" ascii //weight: 1
        $x_1_4 = "NoFolderOptions" ascii //weight: 1
        $x_1_5 = "DisableRegistryTools" ascii //weight: 1
        $x_1_6 = "Fichiers.exe" ascii //weight: 1
        $x_1_7 = "Saves.exe" ascii //weight: 1
        $x_1_8 = "450D8FBA-AD25-11D0-98A8-0800361B1103" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_EH_2147610701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.EH"
        threat_id = "2147610701"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd.exe /c net stop \"Norton AntiVirus Server\"" wide //weight: 1
        $x_1_2 = "auto.exe" wide //weight: 1
        $x_1_3 = "Autorun.inf" wide //weight: 1
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-255] 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_5 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\KavStart" wide //weight: 1
        $x_1_6 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\360Safetray" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_EI_2147610702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.EI"
        threat_id = "2147610702"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d [0-32] 2e 73 63 72}  //weight: 1, accuracy: Low
        $x_1_2 = "[autorun]" ascii //weight: 1
        $x_1_3 = "autorun.inf" ascii //weight: 1
        $x_1_4 = "TaskMonitor" ascii //weight: 1
        $x_1_5 = "Realshade" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "wmnzelf.bat" ascii //weight: 1
        $x_1_8 = "kbdoxhelp.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_EK_2147610703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.EK"
        threat_id = "2147610703"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[AutoRun]" ascii //weight: 1
        $x_1_2 = "gg_ie" ascii //weight: 1
        $x_1_3 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_4 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
        $x_1_5 = "net.exe stop " ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\NOHIDDEN" ascii //weight: 1
        $x_1_7 = "autorun.inf" ascii //weight: 1
        $x_1_8 = {73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d [0-8] 2e 63 6f 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_EN_2147610705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.EN"
        threat_id = "2147610705"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Autorun.inf" ascii //weight: 1
        $x_1_2 = "[AutoRun]" ascii //weight: 1
        $x_1_3 = "shell\\open\\Command=Recycled.exe -e" ascii //weight: 1
        $x_1_4 = {ff 15 40 70 40 00 6a 07 8d ?? ?? ?? 50 ff d7 68 ?? ?? ?? ?? 6a 68 6a 00 ff 15 44 70 40 00 8b f0 85 f6 0f ?? ?? ?? 00 00 56 6a 00 ff 15 48 70 40 00 56 6a 00 ?? ?? ?? ?? ff 15 4c 70 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_ES_2147610732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ES"
        threat_id = "2147610732"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_3 = "http://kkkkb.com" ascii //weight: 1
        $x_1_4 = "Autorun.inf" ascii //weight: 1
        $x_1_5 = "[AutoRun]" ascii //weight: 1
        $x_1_6 = "Command=Drive.exe" ascii //weight: 1
        $x_1_7 = "QQ2007ini" ascii //weight: 1
        $x_1_8 = "hpxk2007" ascii //weight: 1
        $x_1_9 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_10 = "C:\\WINDOWS\\SYSTEM32\\QQ2007\\QQ.ex0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_EO_2147610734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.EO"
        threat_id = "2147610734"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "28C4C820-401A-101B-A3C9-08002B2F49FB" wide //weight: 1
        $x_1_2 = "[autorun]" wide //weight: 1
        $x_1_3 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 41 00 75 00 74 00 6f 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "autorun.inf" wide //weight: 1
        $x_1_5 = {61 00 74 00 74 00 72 00 69 00 62 00 20 00 2b 00 53 00 20 00 2b 00 48 00 20 00 43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 5c 00 44 00 61 00 74 00 61 00 62 00 61 00 73 00 65 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_7 = "DisableTaskMgr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_EQ_2147610735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.EQ"
        threat_id = "2147610735"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetDiskFreeSpaceExA" ascii //weight: 1
        $x_1_2 = "autorun.inf" ascii //weight: 1
        $x_1_3 = "[autorun]" ascii //weight: 1
        $x_1_4 = "shell\\open\\command=RECYCLER\\systems.com" ascii //weight: 1
        $x_1_5 = "taskmger.com" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_7 = "MyPictures.exe" ascii //weight: 1
        $x_1_8 = "DisableTaskmgr" ascii //weight: 1
        $x_1_9 = "DisableRegistryTools" ascii //weight: 1
        $x_1_10 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_ER_2147610736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ER"
        threat_id = "2147610736"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKCU\\Software\\Microsoft\\Internet Explorer\\Main\" /v \"Start Page\" /t REG_EXPAND_SZ /d" ascii //weight: 1
        $x_1_2 = "HKCU\\Software\\Policies\\Microsoft\\Internet Explorer\\Control Panel\" /v \"HomePage\" /t REG_DWORD /d 00000001 /f" ascii //weight: 1
        $x_1_3 = "autorun.inf" ascii //weight: 1
        $x_1_4 = "[AutoRun]" ascii //weight: 1
        $x_1_5 = "shell\\open\\Command=GHO.exe" ascii //weight: 1
        $x_1_6 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /V crsss /T REG_SZ /D" ascii //weight: 1
        $x_1_7 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_dword /d 00000001 /f" ascii //weight: 1
        $x_1_8 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL /v CheckedValue /t REG_dword /d 00000000 /f" ascii //weight: 1
        $x_1_9 = "if exist \"%s\" goto try" ascii //weight: 1
        $x_1_10 = "del %0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_EU_2147610737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.EU"
        threat_id = "2147610737"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Program Files\\Common Files\\System\\wabres.dll" ascii //weight: 1
        $x_1_2 = "645FF040-5081-101B-9F08-00AA002F954E" ascii //weight: 1
        $x_1_3 = "[autorun]" ascii //weight: 1
        $x_1_4 = "shellexecute=.\\Recycled\\rundll32.exe" ascii //weight: 1
        $x_1_5 = "Autorun.inf" ascii //weight: 1
        $x_1_6 = "Riched32.dll" ascii //weight: 1
        $x_1_7 = "Program\\Thunder.ico" ascii //weight: 1
        $x_1_8 = "SOFTWARE\\Thunder Network\\ThunderOem\\thunder_backwnd" ascii //weight: 1
        $x_1_9 = "CreateMutexA" ascii //weight: 1
        $x_1_10 = "GetTickCount" ascii //weight: 1
        $x_1_11 = "WinExec" ascii //weight: 1
        $x_1_12 = "SOFTWARE\\TENCENT\\QQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_EV_2147610738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.EV"
        threat_id = "2147610738"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "goto selfkill" ascii //weight: 1
        $x_1_2 = "InternetOpenA" ascii //weight: 1
        $x_1_3 = "LoadResource" ascii //weight: 1
        $x_1_4 = "ShellExecuteA" ascii //weight: 1
        $x_1_5 = "557B9038-FC87-453C-8B08-32D85F46EAC4" ascii //weight: 1
        $x_1_6 = "Apron_Run" ascii //weight: 1
        $x_1_7 = "IE_HIDE_Run" ascii //weight: 1
        $x_1_8 = "http://www.netwang.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_EV_2147610738_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.EV"
        threat_id = "2147610738"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 65 78 65 20 66 6c 61 73 68 69 6e 66 2e 64 6c 6c 20 4d 73 67 00 00 00 ff ff ff ff 04 00 00 00 6f 70 65 6e 00 00 00 00 ff ff ff ff 07 00 00 00 41 75 74 6f 52 75 6e 00 ff ff ff ff 0c 00 00 00 73 68 65 6c 6c 65 78 65 63 75 74 65 00 00 00 00 ff ff ff ff 12 00 00 00 73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 00 00 ff ff ff ff 12 00 00 00 73 68 65 6c 6c 5c 4f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00 00 ff ff ff ff 12 00 00 00 73 68 65 6c 6c 5c 46 69 6e 64 5c 63 6f 6d 6d 61}  //weight: 1, accuracy: High
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "dolphin61.dll MsgStart" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_EY_2147610843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.EY"
        threat_id = "2147610843"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\windows\\CurrentVersion\\Run\\B" wide //weight: 1
        $x_1_2 = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\system\\DisableTaskMgr" wide //weight: 1
        $x_1_3 = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\system\\DisableRegistryTools" wide //weight: 1
        $x_1_4 = "autorun.inf" wide //weight: 1
        $x_1_5 = "[autorun]" wide //weight: 1
        $x_1_6 = "shell\\open\\command=BkavPro.exe open" wide //weight: 1
        $x_1_7 = "ch Khoa AntiVirus" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_EZ_2147610844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.EZ"
        threat_id = "2147610844"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "autorun.inf" wide //weight: 1
        $x_1_2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Hidden" wide //weight: 1
        $x_1_3 = "[AUTORUN]" wide //weight: 1
        $x_1_4 = "shellexecute=gollum.exe" wide //weight: 1
        $x_1_5 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskmgr" wide //weight: 1
        $x_1_6 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableRegistryTools" wide //weight: 1
        $x_1_7 = "All [*.dll] will be deleted.Sorry your PC was infected with Gollum Virus" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_FA_2147610945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.FA"
        threat_id = "2147610945"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b 00 69 00 6c 00 6c 00 2e 00 62 00 61 00 74 00 00 00 00 00 0c 00 00 00 3a 00 72 00 65 00 64 00 65 00 6c 00 00 00 00 00 04 00 00 00 01 00 88 00 08 00 00 00 64 00 65 00 6c 00 20 00 00 00 00 00 08 00 00 00 2e 00 65 00 78 00 65 00 00 00 00 00 04 00 00 00 01 00 8c 00 12 00 00 00 69 00 66 00 20 00 65 00 78 00 69 00 73 00 74 00 20 00 00 00 16 00 00 00 20 00 67 00 6f 00 74 00 6f 00 20 00 72 00 65 00 64 00 65 00 6c 00 00 00 0c 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 46 00 6f 00 6e 00 74 00 73 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "regwrite" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_FB_2147610947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.FB"
        threat_id = "2147610947"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "9368265E-85FE-11d1-8BE3-0000F8754DA1" wide //weight: 1
        $x_1_2 = "attrib -S -H -R" wide //weight: 1
        $x_1_3 = "autorun.inf" wide //weight: 1
        $x_1_4 = "[autorun]" wide //weight: 1
        $x_1_5 = "shell\\Auto\\command=Recycler\\USBplice.exe" wide //weight: 1
        $x_1_6 = "del C:\\KVUSB.BAT" wide //weight: 1
        $x_1_7 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\USBplice" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_FC_2147610948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.FC"
        threat_id = "2147610948"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://worldnews.ath.cx/update" ascii //weight: 1
        $x_1_2 = "1AEFA55F-60A6-4817-B2D5-12E2E48617F4" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "shell\\open\\Command=rundll32.exe" ascii //weight: 1
        $x_1_5 = "[autorun]" ascii //weight: 1
        $x_1_6 = "wowmgr_is_loaded" ascii //weight: 1
        $x_1_7 = "Command=rundll32.exe .\\\\%s,InstallM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Worm_Win32_Autorun_FE_2147610951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.FE"
        threat_id = "2147610951"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_2 = "Userinit" ascii //weight: 1
        $x_1_3 = "S-1-5-21-4351746447-283674175-7835251345-500" ascii //weight: 1
        $x_1_4 = "taskmgr.exe" ascii //weight: 1
        $x_1_5 = "mj36.exe" ascii //weight: 1
        $x_1_6 = "AutoRun.inf" ascii //weight: 1
        $x_1_7 = "[AutoRun]" ascii //weight: 1
        $x_1_8 = "shell\\explore\\command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_PA_2147611288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.PA"
        threat_id = "2147611288"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6a 00 6a 10 6a 01 6a 00 6a 05 68 86 00 00 00 6a 00 6a 00 6a 00 68 84 03 00 00 6a 00 6a 00 6a 00 6a 1e ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {49 6e 20 4d 65 6d 6f 72 79 20 4f 66 20 43 38 43 00}  //weight: 1, accuracy: High
        $x_1_3 = {bd f6 d2 d4 b4 cb b5 bf c4 ee b1 c8 bc e7 21 00}  //weight: 1, accuracy: High
        $x_1_4 = {ce f7 c4 cf c3 f1 d7 e5 b4 f3 d1 a7 d4 f8 be ad b5 c4 42 42 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_FL_2147611324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.FL"
        threat_id = "2147611324"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8a 5d f8 80 fb 41 74 ?? 80 fb 42 74 ?? 8d 45 f3 50 e8 ?? ?? ?? ?? 83 f8 02 75}  //weight: 3, accuracy: Low
        $x_5_2 = {75 21 6a 02 68 70 f1 00 00 68 12 01 00 00 a1 ?? ?? ?? ?? 8b 00 8b 40 ?? 50 e8 ?? ?? ?? ?? e9 ?? ?? ?? 00 8b 45 fc ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 75 21 6a ff 68 70 f1 00 00 68 12 01 00 00}  //weight: 5, accuracy: Low
        $x_1_3 = {5b 61 75 74 6f 72 75 6e 5d 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 75 74 6f 72 75 6e 2e 69 6e 66 00}  //weight: 1, accuracy: High
        $x_1_5 = "serial=" ascii //weight: 1
        $x_1_6 = "version=" ascii //weight: 1
        $x_1_7 = ":*:Enabled:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_FN_2147611352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.FN"
        threat_id = "2147611352"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 75 74 6f 72 75 6e 2e 69 6e 66 00}  //weight: 1, accuracy: High
        $x_1_2 = "DirectX.bat" ascii //weight: 1
        $x_1_3 = "N-1-5-21-1895222279-3129831995-389225551-6003" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_XFR_2147611367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.XFR"
        threat_id = "2147611367"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 78 65 00 2a 73 68 65 6c 6c 65 78 43 6f 6e 74 65 78 74 4d 65 6e 75 48 61 6e 64 6c 65 72 73 4b 61 73 70 65 72 73 6b 79 20 41 6e 74 69 2d 56 69 72 75 73 00 63 6d 64 20 2f 63 20 52 45 47 20 41 44 44 20 5c 5c 2e 5c 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 20 77 69 6e 33 32 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 25 73 00 00 57 69 6e 33 32 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_PB_2147611391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.PB"
        threat_id = "2147611391"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hideproc" wide //weight: 1
        $x_1_2 = "\\autorun.inf" wide //weight: 1
        $x_1_3 = "shell\\AutoPlay\\Command=kazme__gheyz.exe /open" wide //weight: 1
        $x_1_4 = "shell\\explore\\Command=kazme__gheyz.exe /Explore" wide //weight: 1
        $x_1_5 = "%SYSTEMROOT%\\explorer.exe, %SYSTEMROOT%\\virus.exe" wide //weight: 1
        $x_1_6 = "\\Project\\Fuck\\Project1.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_BR_2147611562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!BR"
        threat_id = "2147611562"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 10
        $x_10_2 = "\\autorun.inf" wide //weight: 10
        $x_10_3 = "[autorun]" wide //weight: 10
        $x_10_4 = "open\\command=" wide //weight: 10
        $x_1_5 = "REG add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 1 /f" wide //weight: 1
        $x_1_6 = "REG add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableRegistryTools /t REG_DWORD /d 1 /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_PC_2147611633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.PC"
        threat_id = "2147611633"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[autorun]" wide //weight: 10
        $x_10_2 = "shell\\open\\Command=" wide //weight: 10
        $x_10_3 = "shell\\open\\Default=1" wide //weight: 10
        $x_1_4 = {7b 00 46 00 31 00 32 00 7d 00 00 00 18 00 00 00 7b 00 53 00 68 00 69 00 66 00 74 00 7d 00 7b 00 46 00 31 00 32 00 7d 00 00 00 00 00 18 00 00 00 7b 00 2a 00 20 00 6f 00 6e 00 20 00 23 00 20 00 70 00 61 00 64 00 7d}  //weight: 1, accuracy: High
        $x_2_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Sysanalysing" wide //weight: 2
        $x_1_6 = "Software\\Microsoft\\Internet Explorer\\Main\\FormSuggest PW Ask" wide //weight: 1
        $x_1_7 = "Software\\Microsoft\\Internet Explorer\\Main\\FormSuggest Passwords" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_PD_2147611678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.PD"
        threat_id = "2147611678"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ":\\autorun.inf" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\msvd32srv" ascii //weight: 1
        $x_1_3 = {2d 77 61 69 74 [0-24] 6d 73 76 64 33 32 73 72 76 [0-12] 2d 66 6c 61 73 68 [0-12] 65 78 70 6c 6f 72 65 72 2e 65 78 65 [0-12] 3a 5c [0-3] 64 33 62 37 75 65 35 38 79 37 6a 62 64 73}  //weight: 1, accuracy: Low
        $x_1_4 = "[autorun]" ascii //weight: 1
        $x_1_5 = {2d 66 6c 61 73 68 [0-10] 49 43 4f 4e 3d 73 68 65 6c 6c 33 32 2e 64 6c 6c 2c 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_GG_2147612316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.GG"
        threat_id = "2147612316"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 69 6e 65 31 20 3d 20 22 5b 61 75 74 6f 72 75 6e 5d 22 20 26 26 20 6c 69 6e 65 32 20 3d 20 22 6f 70 65 6e 20 3d 20 53 79 73 74 65 6d 5c 44 72 69 76 65 47 75 61 72 64 5c 44 72 69 76 65 50 72 6f 74 65 63 74 2e 65 78 65 20 2d 72 75 6e a0 22 20 26 26}  //weight: 1, accuracy: High
        $x_1_2 = {5f 5f 0d 0a 0d 0a 54 68 69 73 20 74 6f 6f 6c 20 69 73 20 74 6f 20 70 72 6f 74 65 63 74 20 72 65 6d 6f 76 61 62 6c 65 20 73 74 6f 72 61 67 65 0d 0a 64 65 76 69 63 65 73 20 66 72 6f 6d 20 6d 61 6c 77 61 72 65 73 2e 0d 0a 5f 5f}  //weight: 1, accuracy: High
        $x_1_3 = "filesetattrib, -RASH, %thsdrv%\\autorun.inf" ascii //weight: 1
        $x_1_4 = {4c 6f 6f 70 2c 20 25 75 73 65 72 70 72 6f 66 69 6c 65 25 5c 4c 6f 63 61 6c 20 53 65 74 74 69 6e 67 73 5c 54 65 6d 70 6f 72 61 72 79 20 49 6e 74 65 72 6e 65 74 20 46 69 6c 65 73 5c 2a 2e 6a 70 67 2c 31 2c 31 0d 0a 7b 0d 0a 49 66 20 41 5f 4c 6f 6f 70 66 69 6c 65 6e 61 6d 65 20 63 6f 6e 74 61 69 6e 73 20 55 70 64 61 74 65 4b 42}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Autorun_PI_2147612736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.PI"
        threat_id = "2147612736"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {f7 d8 1b c0 40 23 f0 f7 de 1b f6 f7 de 8b ?? ?? ?? 41 00}  //weight: 3, accuracy: Low
        $x_3_2 = {b8 04 00 02 80 89 85 ?? ff ff ff b9 0a 00 00 00 89 8d ?? ff ff ff 83 ec 10 8b d4 89 0a 8b 8d ?? ff ff ff 89 4a 04 89 42 08 8b 85 ?? ff ff ff 89 42 0c}  //weight: 3, accuracy: Low
        $x_1_3 = "arquivos.exe" wide //weight: 1
        $x_1_4 = "New Documento do Microsoft Word.exe" wide //weight: 1
        $x_1_5 = "lstCMD.txt" wide //weight: 1
        $x_1_6 = "ftp_remote_port" wide //weight: 1
        $x_1_7 = "ftp_password" wide //weight: 1
        $x_1_8 = "w5335a0.ath.cx" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_YB_2147615108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.YB"
        threat_id = "2147615108"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6d 79 64 6f 77 6e 2e 61 73 70 3f 76 65 72 3d 30 38 31 30 [0-2] 26 74 67 69 64 3d [0-16] 26 61 64 64 72 65 73 73 3d 30 30 2d 30 30 2d 30 30 2d 30 30 2d 30 30 2d 30 30}  //weight: 10, accuracy: Low
        $x_10_2 = "C:\\WINDOWS\\mydown.asp" ascii //weight: 10
        $x_1_3 = "ShuiNiu.exe" ascii //weight: 1
        $x_1_4 = "qqm.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_PL_2147615353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.PL"
        threat_id = "2147615353"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mourn_Operator.exe" wide //weight: 1
        $x_1_2 = "AUTORUN.INF" wide //weight: 1
        $x_1_3 = {75 72 6e 5f 4f 70 4d 6f 75 72 6e 5f 4f 70 65 72 61 74 6f 72 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "[AUTORUN]" wide //weight: 1
        $x_1_5 = "SYSANALYSIS.EXE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_PR_2147616370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.PR"
        threat_id = "2147616370"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Autorun]" wide //weight: 1
        $x_1_2 = "UseAutoPlay=1" wide //weight: 1
        $x_1_3 = "Icon=%SystemRoot%\\system32\\shell32.dll,7" wide //weight: 1
        $x_1_4 = "Action=Open disk to view files" wide //weight: 1
        $x_1_5 = "Open=FOUND.007.exe" wide //weight: 1
        $x_1_6 = "ShellExecute=FOUND.007.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_PS_2147616416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.PS"
        threat_id = "2147616416"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 ff d6 83 f8 02 74 4c fe c3 80 fb 5a 7e d7}  //weight: 1, accuracy: High
        $x_1_2 = "shell\\Auto\\command=" ascii //weight: 1
        $x_1_3 = "[AutoRun]" ascii //weight: 1
        $x_1_4 = "shellexecute=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_PT_2147616448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.PT"
        threat_id = "2147616448"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MJ_CENTRO" ascii //weight: 1
        $x_1_2 = "MJ_FUNCIONES" ascii //weight: 1
        $x_1_3 = "MJ_MOTOR" ascii //weight: 1
        $x_1_4 = "[Autorun]" wide //weight: 1
        $x_1_5 = "Open=mj.exe" wide //weight: 1
        $x_1_6 = ";shell\\open=Open(&O)" wide //weight: 1
        $x_1_7 = "HKEY_LOCAL_MACHINE\\MariaJose\\Infectados" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Worm_Win32_Autorun_GV_2147616826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.GV"
        threat_id = "2147616826"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 03 74 05 83 f8 02 75 69 68 a0 00 00 00 68 ?? ?? ?? ?? ff d5}  //weight: 1, accuracy: Low
        $x_1_2 = "\\autorun.inf" ascii //weight: 1
        $x_1_3 = "[AutoRun]" ascii //weight: 1
        $x_1_4 = "http://%c%c%c.%c%c%c%c%c%c.%c%c%c/%c.%c%c%c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_GX_2147616846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.GX"
        threat_id = "2147616846"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".cn/ul.htm" ascii //weight: 1
        $x_1_2 = "Recycled.exe" ascii //weight: 1
        $x_1_3 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00 6f 70 65 6e 00 41 75 74 6f 52 75 6e}  //weight: 1, accuracy: High
        $x_1_4 = {64 65 6c 65 74 65 00 2e 45 58 45 00 5c 4e 54 2d}  //weight: 1, accuracy: High
        $x_1_5 = {5b 25 73 25 5d 00 5b 25 70 25 5d 00 5b 25 66 25 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_GY_2147616966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.GY"
        threat_id = "2147616966"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "72"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Autorun.inf" wide //weight: 10
        $x_10_2 = "Software\\Policies\\Microsoft\\MMC" wide //weight: 10
        $x_10_3 = "78E1BDD1-9941-11cf-9756-00AA00C00908" wide //weight: 10
        $x_10_4 = "NoDriveTypeAutoRun" wide //weight: 10
        $x_10_5 = "restrictanonymous" wide //weight: 10
        $x_10_6 = "CreateRemoteThread" ascii //weight: 10
        $x_10_7 = "WTSEnumerateProcessesA" ascii //weight: 10
        $x_1_8 = "Restore\\rstrui.exe" wide //weight: 1
        $x_1_9 = "\\database\\system.ini" wide //weight: 1
        $x_1_10 = "\\Backup\\Autoexec.bat" wide //weight: 1
        $x_1_11 = "\\response.exe modules" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_GZ_2147617002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.GZ"
        threat_id = "2147617002"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\ftproot\\%s" ascii //weight: 1
        $x_1_2 = "WNetOpenEnumW" ascii //weight: 1
        $x_1_3 = "Sex_Game.exe" ascii //weight: 1
        $x_1_4 = "Sex_ScreenSaver.scr" ascii //weight: 1
        $x_1_5 = "autorun.exe" wide //weight: 1
        $x_1_6 = "$systray.exe" wide //weight: 1
        $x_1_7 = "\\My Documents\\Yahood.Jpg" wide //weight: 1
        $x_1_8 = "\\Application Data\\usrinit.exe" wide //weight: 1
        $x_1_9 = "Autorun.inf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Worm_Win32_Autorun_QA_2147617362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.QA"
        threat_id = "2147617362"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[Autorun]" wide //weight: 1
        $x_1_2 = "shell\\open\\Command=FARTHER.exe" wide //weight: 1
        $x_1_3 = "taskkill /f /im 360safe.exe" wide //weight: 1
        $x_1_4 = {c7 45 fc 2f 00 00 00 66 83 7d dc 03 74 05 e9 ?? ?? 00 00 c7 45 fc 32 00 00 00 8b 45 08 83 78 34 00 75 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_PP_2147617849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.PP"
        threat_id = "2147617849"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "311"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "drivers/klif.sys" ascii //weight: 100
        $x_100_2 = "AutoRun.inf" ascii //weight: 100
        $x_100_3 = "Program Files\\Common Files\\Microsoft Shared\\MSINFO" ascii //weight: 100
        $x_10_4 = "FieleWay.txt" ascii //weight: 10
        $x_10_5 = "Beizhu" ascii //weight: 10
        $x_1_6 = "cmd /c date 1981-01-12" ascii //weight: 1
        $x_1_7 = "cmd /c erase /F" ascii //weight: 1
        $x_1_8 = "rejoice" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_HO_2147618260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.HO"
        threat_id = "2147618260"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 08 00 00 00 62 32 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {65 63 68 6f 20 5b 61 75 74 6f 72 75 6e 5d 20 3e 3e 20 25 25 ?? 3a 5c 41 75 74 6f 72 75 6e 2e 69 6e 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_HT_2147618763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.HT"
        threat_id = "2147618763"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%c:\\autorun.inf" ascii //weight: 1
        $x_1_2 = "\\command.com" ascii //weight: 1
        $x_1_3 = "%s\\explorer %c:" ascii //weight: 1
        $x_1_4 = "shellexecute=RECYCLER\\%s" ascii //weight: 1
        $x_1_5 = "%s /c rd %c:\\RECYCLER\\%s /s/q" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_XFV_2147618908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.XFV"
        threat_id = "2147618908"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 [0-10] 77 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {53 00 68 00 65 00 6c 00 6c 00 5c 00 61 00 75 00 74 00 6f 00 5c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 46 00 4f 00 55 00 4e 00 44 00 2e 00 ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Action=Open disk to view files" wide //weight: 1
        $x_1_4 = "c:\\B1uv3nth3x1.diz" wide //weight: 1
        $x_1_5 = "012483 10v3 H3r51.58y.pct" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Autorun_HX_2147618929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.HX"
        threat_id = "2147618929"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "autorun.inf +h +r +s" ascii //weight: 10
        $x_1_2 = {00 6d 6d 2e 65 78 65 20 2b 68 20 2b 72 20 2b 73}  //weight: 1, accuracy: High
        $x_1_3 = "shell\\explore\\Command" ascii //weight: 1
        $x_1_4 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_5 = "f126.com/go/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_HU_2147619015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.HU"
        threat_id = "2147619015"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[AutoRun]" ascii //weight: 1
        $x_1_2 = "%s\\autorun.inf" ascii //weight: 1
        $x_2_3 = "%s\\%d-%d-%d.jpg" ascii //weight: 2
        $x_1_4 = "\\system32\\drivers\\autorun." ascii //weight: 1
        $x_1_5 = "shell\\explore\\Command=%s.exe" ascii //weight: 1
        $x_1_6 = "Administrador de tareas de Windows" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_QG_2147619316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.QG"
        threat_id = "2147619316"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1c 1b 00 1b 4b 00 43 74 ff 1e fb 01 6c 70 ff f5 02 00 00 00 c7 1c 30 00 1b 4c 00 43 74 ff 1e fb 01 6c 70 ff f5 03 00 00 00 c7 1c 45 00 1b 4d 00 43 74 ff 1e}  //weight: 1, accuracy: High
        $x_1_2 = "Autorun.inf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_QI_2147619515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.QI"
        threat_id = "2147619515"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 00 45 00 3a 00 5c 00 e0 65 0d 54 0b 4e 7d 8f 05 80 5c 00 31 00 30 00 2d 00 32 00 30 00 1c 59 0d 4e c7 8f 4e 00 4f 00 44 00 5c 00 0b 4e 7d 8f 5c 00 e5 5d 0b 7a 31 00 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 73 00 75 00 70 00 65 00 72 00 6b 00 69 00 6c 00 6c 00 20 00 a0 52 f3 58 e0 65 0e 54 e8 95 5c 00 0b 4e 7d 8f 5c 00 e5 5d 0b 7a 31 00 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 5c 00 41 00 75 00 74 00 6f 00 5c 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 [0-4] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "KvMonXP.kxp||avp.exe||avp.exe||avp.exe||egui.exe||shstat.exe||" wide //weight: 1
        $x_1_5 = "\\Windows\\CurrentVersion\\Run\\avpx" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_Win32_Autorun_QH_2147619516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.QH"
        threat_id = "2147619516"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "USBMonMutex2.0" wide //weight: 1
        $x_1_2 = "%SystemRoot%\\system32\\usbmons.exe" ascii //weight: 1
        $x_1_3 = {52 45 43 59 43 4c 45 52 5c 52 45 43 59 43 4c 45 52 5c 61 75 74 6f 72 75 6e 2e 65 78 65 [0-16] 61 75 74 6f 72 75 6e 2e 69 6e 66}  //weight: 1, accuracy: Low
        $x_1_4 = {44 6f 47 65 74 57 69 6e 6c 6f 67 6f 6e 50 69 64 21 [0-4] 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 [0-4] 4f 70 65 6e 50 72 6f 63 65 73 73 21}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_IB_2147619778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.IB"
        threat_id = "2147619778"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "callnexthookex" ascii //weight: 1
        $x_1_2 = "autorun.inf" ascii //weight: 1
        $x_1_3 = "IEFrame" ascii //weight: 1
        $x_1_4 = "shell\\Auto\\command=a.exe e" ascii //weight: 1
        $x_1_5 = "c:\\windows\\system32\\a.exe" ascii //weight: 1
        $x_1_6 = "c:\\windows\\system32\\Project1_autorun.exe" ascii //weight: 1
        $x_1_7 = "c:\\windows\\system32\\ICL.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_IC_2147619825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.IC"
        threat_id = "2147619825"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 6f 4e 61 4d 65 78 44 [0-16] 5c 61 75 74 6f 72 75 6e 2e 69 6e 66}  //weight: 1, accuracy: Low
        $x_1_2 = {0d 55 6e 69 74 31 5f 61 75 74 6f 72 75 6e}  //weight: 1, accuracy: High
        $x_1_3 = "SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_JK_2147620502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.JK"
        threat_id = "2147620502"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo [autorun] > %windir%\\Autorun.inf" ascii //weight: 1
        $x_1_2 = "echo open=Winloader.bat >> %windir%\\Autorun.inf" ascii //weight: 1
        $x_1_3 = "shutdown /s /f /t 10 /c \".:::[SORRY]:::.\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_KB_2147620632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.KB"
        threat_id = "2147620632"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "shell\\open\\Command=sysboot.scr" ascii //weight: 10
        $x_10_2 = "autorun.inf" ascii //weight: 10
        $x_10_3 = "Realschade" ascii //weight: 10
        $x_5_4 = "%scopy /Y \"%s\"" ascii //weight: 5
        $x_5_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_KC_2147620637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.KC"
        threat_id = "2147620637"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 52 75 6e [0-8] 48 6f 6f 6b 50 72 6f 63 2e 64 6c 6c [0-4] 65 78 70 6c 6f 72 65 72 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_2 = {48 69 64 65 51 51 [0-4] 48 6f 6f 6b 50 72 6f 63}  //weight: 10, accuracy: Low
        $x_5_3 = "shell\\explore\\Command=" ascii //weight: 5
        $x_1_4 = "autorun.inf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_KF_2147620708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.KF"
        threat_id = "2147620708"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\cyden" wide //weight: 10
        $x_10_2 = "RavDr.exe %1" wide //weight: 10
        $x_10_3 = "shell\\open\\Command=Recycled.exe" wide //weight: 10
        $x_1_4 = "Explorer\\Advanced\\Folder\\Hidden\\SHOWALL\\CheckedValue" wide //weight: 1
        $x_1_5 = "Autorun.inf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_QL_2147620716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.QL"
        threat_id = "2147620716"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 fa 5a 7f 41 8b 45 08 8a 4d fc 88 08 8b f4 8b 55 08 52 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 83 f8 02 74 18}  //weight: 1, accuracy: Low
        $x_1_2 = "shell\\Auto\\command=" ascii //weight: 1
        $x_1_3 = "[AutoRun]" ascii //weight: 1
        $x_1_4 = "shellexecute=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_LB_2147621004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.LB"
        threat_id = "2147621004"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\XqdBho" ascii //weight: 10
        $x_10_2 = "Autorun.inf" ascii //weight: 10
        $x_10_3 = "shell\\Auto\\command" ascii //weight: 10
        $x_5_4 = "SERVICS.EXE" ascii //weight: 5
        $x_5_5 = "SCVH0ST.EXE" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_LC_2147621009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.LC"
        threat_id = "2147621009"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_3 = {63 00 6f 00 70 00 79 00 20 00 70 00 69 00 61 00 6f 00 79 00 61 00 6f 00 2e 00 69 00 6e 00 66 00 [0-4] 3a 00 5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00}  //weight: 10, accuracy: Low
        $x_1_4 = {61 00 74 00 74 00 72 00 69 00 62 00 20 00 2b 00 72 00 20 00 2b 00 73 00 20 00 2b 00 68 00 [0-4] 3a 00 5c 00 41 00 55 00 54 00 4f 00 52 00 55 00 4e 00 2e 00 49 00 4e 00 66 00}  //weight: 1, accuracy: Low
        $x_1_5 = {61 00 74 00 74 00 72 00 69 00 62 00 20 00 2b 00 72 00 20 00 2b 00 73 00 20 00 2b 00 68 00 [0-4] 3a 00 5c 00 70 00 69 00 61 00 6f 00 79 00 61 00 6f 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_QU_2147621022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.QU"
        threat_id = "2147621022"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 98 50 ff 15 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 85 80 fe ff ff ff 15 ?? ?? ?? ?? 33 c9 83 bd 80 fe ff ff 02 0f 94 c1 f7 d9}  //weight: 1, accuracy: Low
        $x_1_2 = "[AutoRun]" wide //weight: 1
        $x_1_3 = "shell\\explore\\Command=''" wide //weight: 1
        $x_1_4 = "SVCH0ST.EXE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_RD_2147621059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.RD"
        threat_id = "2147621059"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "E:\\T@xM@n@g3r\\Project1.vbp" wide //weight: 1
        $x_1_2 = "Explorer /s " wide //weight: 1
        $x_1_3 = "[AUTORUN]" wide //weight: 1
        $x_1_4 = "shell\\open\\Command=BuluBebek.ini" wide //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SPYXX.EXE" wide //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\HideFileExt" wide //weight: 1
        $x_1_7 = "DisableRegistryTools" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Worm_Win32_Autorun_JA_2147621073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.JA"
        threat_id = "2147621073"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "autorun.inf" wide //weight: 1
        $x_1_2 = "[AutoRun]" wide //weight: 1
        $x_1_3 = "NoDriveTypeAutoRun" wide //weight: 1
        $x_1_4 = "OPEN=taiping" wide //weight: 1
        $x_1_5 = "explorer http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_XFX_2147621244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.XFX"
        threat_id = "2147621244"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "@*\\AC:\\as\\hack\\exe proj\\sem\\PROJECT1.VBP" wide //weight: 2
        $x_1_2 = "regedit.exe" wide //weight: 1
        $x_1_3 = "C:\\comand.exe \"%1\" %*" ascii //weight: 1
        $x_1_4 = "Software\\VB and VBA Program Settings\\LnA\\run" ascii //weight: 1
        $x_1_5 = "nevershowext" wide //weight: 1
        $x_1_6 = "dats.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_RE_2147621274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.RE"
        threat_id = "2147621274"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\" ascii //weight: 10
        $x_10_2 = {61 75 74 6f 72 75 6e 2e 69 6e 66 00}  //weight: 10, accuracy: High
        $x_10_3 = {5b 61 75 74 6f 72 75 6e 5d 00}  //weight: 10, accuracy: High
        $x_10_4 = {52 45 47 20 41 44 44 20 48 4b 45 59 5f [0-16] 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 20}  //weight: 10, accuracy: Low
        $x_1_5 = "open=RECYCLER\\" ascii //weight: 1
        $x_1_6 = "shell\\open\\Command=RECYCLER\\" ascii //weight: 1
        $x_1_7 = "shell\\explore\\Command=RECYCLER\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_YC_2147622427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.YC"
        threat_id = "2147622427"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {75 72 74 6f 72 62 72 6f 00 70 72 6a 44 6f 77 6e 6c 6f 61 64 65 64}  //weight: 10, accuracy: High
        $x_10_2 = {70 72 6a 44 6f 77 6e 6c 6f 61 64 65 72 00 00 00 16 00 00 00 75 00 73 00 62 00 68 00 65 00 6c 00 70 00 2e 00 65 00 78 00 65}  //weight: 10, accuracy: High
        $x_5_3 = "*\\AC:\\Documents and Settings\\Matt\\Desktop\\Visual Basic\\VB6 Downloader\\prjDownloader.vbp" wide //weight: 5
        $x_5_4 = "autorun.inf" wide //weight: 5
        $x_1_5 = "madtorrents.info/usb.php?msgg=Infected From USB Drive" wide //weight: 1
        $x_1_6 = "madtorrents.info/payloads/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_QZ_2147622743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.QZ"
        threat_id = "2147622743"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fuckrising" wide //weight: 1
        $x_1_2 = "AutoRun.inf" wide //weight: 1
        $x_1_3 = "emailforms/email_action.asp?section=about&sectionbanner=banner_about.jpg&email=" wide //weight: 1
        $x_1_4 = "shell\\open\\command=SysWin32.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_QAB_2147622830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.QAB"
        threat_id = "2147622830"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {75 73 62 63 61 73 68 2e 65 78 65 [0-48] 41 75 74 6f 52 75 6e 2e 69 6e 66 [0-48] 5b 41 75 74 6f 52 75 6e 5d}  //weight: 10, accuracy: Low
        $x_10_2 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 [0-48] 73 68 65 6c 6c 5c 6f 70 65 6e 5c 44 65 66 61 75 6c 74}  //weight: 10, accuracy: Low
        $x_10_3 = "TWormUSB" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_QAC_2147622868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.QAC"
        threat_id = "2147622868"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6b 65 79 72 65 63 6f 72 64 5f 6d 73 28 25 64 25 64 25 64 25 64 25 64 25 64 29 2e 74 78 74 [0-4] 5b 61 75 74 6f 72 75 6e 5d [0-4] 4f 50 45 4e 3d 52 65 63 79 63 6c 65 63 6c 5c 45 58 50 4c 4f 52 45 2e 45 58 45 [0-4] 73 68 65 6c 6c 5c 6f 70 65 6e 3d}  //weight: 10, accuracy: Low
        $x_10_2 = "[longsky server: v2.0 test version" ascii //weight: 10
        $x_10_3 = {53 65 74 4b 42 48 6f 6f 6b 45 6e 40 40 59 41 5f 4e 58 5a [0-4] 3f 53 65 74 4d 53 48 6f 6f 6b 40 40 59 41 5f 4e 58 5a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_LD_2147623000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.LD"
        threat_id = "2147623000"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "[AutoRun]" wide //weight: 10
        $x_10_2 = ":\\autorun.inf" wide //weight: 10
        $x_10_3 = {6f 00 70 00 65 00 6e 00 3d 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_10_4 = {73 00 68 00 65 00 6c 00 6c 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 3d 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_10_5 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_1_6 = "\\All Users\\Desktop\\Desktop.exe" wide //weight: 1
        $x_1_7 = ":\\My Documents.exe" wide //weight: 1
        $x_1_8 = ":\\My Pictures.exe" wide //weight: 1
        $x_1_9 = "\\security\\uvchost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_JP_2147623015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.JP"
        threat_id = "2147623015"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@*\\AC:\\server\\Tarantula.vbp" wide //weight: 1
        $x_1_2 = "=dnammoc\\nepo\\llehs" wide //weight: 1
        $x_1_3 = "fni.nurotua" wide //weight: 1
        $x_1_4 = "sovihcra rev arap ateprac rirbA=noitca" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Autorun_MA_2147623122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.MA"
        threat_id = "2147623122"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EB0EE8xxxxx01x83F80274" wide //weight: 1
        $x_1_2 = "ll\\open\\Command=" wide //weight: 1
        $x_1_3 = "type=hidden" wide //weight: 1
        $x_1_4 = "Send E-Mail" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_QAD_2147623198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.QAD"
        threat_id = "2147623198"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\install.exe" wide //weight: 1
        $x_1_2 = ":\\autorun.inf" wide //weight: 1
        $x_1_3 = "C:\\vidc20.exe" wide //weight: 1
        $x_1_4 = "C:\\selill3.bat" wide //weight: 1
        $x_1_5 = {73 00 68 00 65 00 6c 00 00 00 00 00 0a 00 00 00 6c 00 5c 00 6f 00 70 00 65 00 00 00 0c 00 00 00 6e 00 5c 00 43 00 6f 00 6d 00 6d 00 00 00 00 00 1e 00 00 00 61 00 6e 00 64 00 3d 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_QAE_2147623459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.QAE"
        threat_id = "2147623459"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-16] 43 3a 5c 57 69 6e 64 6f 77 73 5c 73 76 63 68 6f 73 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 5c [0-16] 68 74 74 70 3a 2f 2f 77 77 77 2e 7a 69 78 7a 65 6c 7a 31 2e 6e 61 72 6f 64 2e 72 75 2f [0-16] 53 74 61 72 74 20 50 61 67 65}  //weight: 1, accuracy: Low
        $x_1_3 = ":\\Films.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_JT_2147623746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.JT"
        threat_id = "2147623746"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_1_2 = "software\\Classes\\CLSID\\TTLSERVICE" ascii //weight: 1
        $x_1_3 = "\\TTLService.exe" ascii //weight: 1
        $x_1_4 = "ActService" ascii //weight: 1
        $x_1_5 = "\\Autorun\\Autorun.exe" ascii //weight: 1
        $x_1_6 = "\\Autorun.inf" ascii //weight: 1
        $x_1_7 = "Open=autorun\\autorun.exe" ascii //weight: 1
        $x_1_8 = "shellexecute=AutoRun\\Autorun.exe" ascii //weight: 1
        $x_1_9 = "(&O)\\command=autorun\\autorun.exe" ascii //weight: 1
        $x_1_10 = "software\\microsoft\\windows\\currentversion\\run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_JV_2147623976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.JV"
        threat_id = "2147623976"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[AUTORUN]" wide //weight: 1
        $x_1_2 = "inf\\drvindex.inf" wide //weight: 1
        $x_1_3 = {f5 00 00 00 00 6c 58 ff 1b 1d 00 2a 23 20 ff 1b 17 00 2a 46 48 ff}  //weight: 1, accuracy: High
        $x_1_4 = {f5 27 00 00 00 6c 2c ff 1b 7e 00 2a 23 24 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_JW_2147624026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.JW"
        threat_id = "2147624026"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SeDebugPrivilege" wide //weight: 1
        $x_1_2 = "*\\AC:\\Project7\\Project1.vbp" wide //weight: 1
        $x_1_3 = "GetDriveTypeA" ascii //weight: 1
        $x_1_4 = "SetCurrentDirectoryA" ascii //weight: 1
        $x_1_5 = "ShellExecuteA" ascii //weight: 1
        $x_1_6 = "RtlSetProcessIsCritical" ascii //weight: 1
        $x_1_7 = "InternetOpenA" ascii //weight: 1
        $x_1_8 = "69B16CF356FF75F0611F5F92D4A8" wide //weight: 1
        $x_1_9 = "wH22vou10Dr0I3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_RL_2147624114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.RL"
        threat_id = "2147624114"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 02 74 18 53 e8 ?? ?? ?? ?? 83 f8 05 75 0d}  //weight: 1, accuracy: Low
        $x_1_2 = "shell/autoplay/command=NewFolder.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_RM_2147624253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.RM"
        threat_id = "2147624253"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 99 83 e2 03 8b 8c 24 ?? ?? ?? ?? 03 c2 c1 f8 02 8a 44 87 fc c6 44 24 0d 3a 88 44 24 0c 8b c1 48 c6 44 24 0e 5c}  //weight: 1, accuracy: Low
        $x_1_2 = {5b 41 75 74 6f 52 75 6e 5d 0d 0a 6f 70 65 6e 3d 2e 5c 4d 53 4f 43 61 63 68 65 5c 39 30 30 30 30 38 30 34 2d 36 30 30 30 2d 31 31 44 33 2d 38 43 46 45 2d 30 31 35 30 30 34 38 33 38 33 43 39 5c 4b 42 39 31 35 38 36 35 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_JZ_2147624322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.JZ"
        threat_id = "2147624322"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Model=HelloPhilippines" wide //weight: 10
        $x_1_2 = "BugIndependent\\HelloPhilippines.vbp" wide //weight: 1
        $x_1_3 = "\\taskmgr.exe" wide //weight: 1
        $x_1_4 = "Autorun.inf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_LF_2147624325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.LF"
        threat_id = "2147624325"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "*\\Ad:\\Belajar\\MrX1\\MrX.vbp" wide //weight: 10
        $x_1_2 = "\\Device\\PhysicalMemory" wide //weight: 1
        $x_1_3 = "RegWrite" wide //weight: 1
        $x_1_4 = "shell\\Auto\\command=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_LG_2147624340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.LG"
        threat_id = "2147624340"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 02 0f 84 ?? ?? 00 00 48 0f 85 ?? ?? 00 00 8b 8d ?? ?? ff ff 8b 84 8d ?? ?? ff ff e8}  //weight: 1, accuracy: Low
        $x_1_2 = {5b 41 75 74 6f 52 75 6e 5d 00 53 68 65 6c 6c 45 78 65 63 75 74 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_RP_2147624451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.RP"
        threat_id = "2147624451"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\XDOc\\Nouveau dossier\\Copie (3) de MyDOc\\GuelmimGhost3.vbp" wide //weight: 1
        $x_1_2 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 5c 00 00 00 00 00 10 00 00 00 5a 00 61 00 6b 00 61 00 72 00 69 00 61 00 47 00}  //weight: 1, accuracy: High
        $x_1_3 = "set Guelmim = createobject(\"Wscript.shell\")" ascii //weight: 1
        $x_1_4 = "c:\\windows\\system32\\ZakariaG.jpg.exe" wide //weight: 1
        $x_1_5 = "cmd.exe /c start c:\\windows\\system32\\z.vbs" wide //weight: 1
        $x_1_6 = "HideFileExt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_RQ_2147624521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.RQ"
        threat_id = "2147624521"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\MY Project\\Viros\\Copy To file and drive auto\\dircve\\Project1.vbp" wide //weight: 1
        $x_1_2 = "roomezonline.persiangig.com/password/mlogginf32.exe" wide //weight: 1
        $x_1_3 = {52 00 65 00 67 00 53 00 76 00 72 00 33 00 32 00 00 00 00 00 02 00 00 00 20 00 00 00 18 00 00 00 5c 00 41 00 4f 00 53 00 4d 00 54 00 50 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 00 00 00 00 72 00 65 00 67 00 77 00 72 00 69 00 74 00 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 66 00 69 00 6e 00 64 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 62 00 6f 00 6f 00 74 00 2e 00 65 00 78 00 65 00 00 00 18 00 00 00 5c 00 41 00 55 00 54 00 4f 00 52 00 55 00 4e 00 2e 00 49 00 4e 00 46 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_LL_2147624596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.LL"
        threat_id = "2147624596"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[AutoRun]" wide //weight: 10
        $x_10_2 = "\\autorun.inf" wide //weight: 10
        $x_10_3 = "strPasswdToRecover" ascii //weight: 10
        $x_10_4 = "enCrYpteD" wide //weight: 10
        $x_10_5 = "DeCrYpteD" wide //weight: 10
        $x_10_6 = "\\svchost32.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_LQ_2147624711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.LQ"
        threat_id = "2147624711"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 6f 77 72 70 72 6f 66 00 00 00 00 10 00 00 00 53 65 74 53 75 73 70 65 6e 64 53 74 61 74 65 00 0c 00 00 00 68 00 63 00 75 00 72 00 75 00 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {41 00 3a 00 00 00 00 00 04 00 00 00 42 00 3a 00 00 00 00 00 08 00 00 00 66 00 69 00 6c 00 65 00 00 00 00 00 08 00 00 00 57 00 33 00 32 00 2e 00 00 00 00 00 0a 00 00 00 2e 00 57 00 6f 00 72 00 6d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_LS_2147624790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.LS"
        threat_id = "2147624790"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Select ID_PC from" wide //weight: 1
        $x_1_2 = "autorun.inf" wide //weight: 1
        $x_1_3 = "[autorun]" wide //weight: 1
        $x_1_4 = "autorun.exe" wide //weight: 1
        $x_1_5 = "Este arquivo cont" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_LV_2147625036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.LV"
        threat_id = "2147625036"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "[AUTORUN]" wide //weight: 4
        $x_1_2 = {74 6d 72 4b 69 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {61 00 76 00 67 00 65 00 6d 00 63 00 2e 00 65 00 78 00 65 00 [0-16] 63 00 63 00 61 00 70 00 70 00 73 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {68 00 69 00 6a 00 61 00 63 00 6b 00 74 00 68 00 69 00 73 00 [0-16] 73 00 79 00 73 00 69 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 73 00}  //weight: 1, accuracy: Low
        $x_1_5 = "McAfeeVirusScanCentral" wide //weight: 1
        $x_1_6 = "DisableRegistryTools" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_RU_2147625543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.RU"
        threat_id = "2147625543"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Thumbs.exe" ascii //weight: 1
        $x_1_2 = "[autorun]" ascii //weight: 1
        $x_1_3 = "shell\\PRM\\command = Thumbs.exe -start" ascii //weight: 1
        $x_1_4 = "Hi, I'm virus" ascii //weight: 1
        $x_1_5 = "Format C: [-] ." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_RV_2147625549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.RV"
        threat_id = "2147625549"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1% = nepo|1% = noci|]nurotua[" wide //weight: 1
        $x_1_2 = "fni.nurotua" wide //weight: 1
        $x_1_3 = {5e 21 00 04 00 71 78 ff 00 0e 6c 78 ff f5 03 00 00 00 c7 1c 5a 01 00 2a 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_TO_2147625687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.TO"
        threat_id = "2147625687"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\chit\\MORGANUSBINFECTOR\\TPWrm2.vbp" wide //weight: 1
        $x_1_2 = "A:\\lieke.ex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_RZ_2147626446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.RZ"
        threat_id = "2147626446"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "testcataloge.by.ru/" ascii //weight: 1
        $x_1_2 = "shell\\open\\Command=zetup.exe" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_4 = "RCPT TO: <" ascii //weight: 1
        $x_1_5 = "SELECT * FROM Win32_BIOS,SerialNumber" ascii //weight: 1
        $x_1_6 = "fasm.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_MI_2147626506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.MI"
        threat_id = "2147626506"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 5c 61 75 74 89 04 24 8d bd ?? ?? ff ff bb 6f 72 75 6e 8b 4c 95 ?? 89 4c 24 ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {44 3a 00 45 3a 00 46 3a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_UB_2147627109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.UB"
        threat_id = "2147627109"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 44 53 e8 ?? ?? ?? ?? 83 f8 02 75 36 8a 03 3c 41 74 30 3c 42 74 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f0 04 83 f0 02 83 f0 01 50 8b 45 ec 8b 04 98 e8 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {5b 61 75 74 6f 72 75 6e 5d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_UC_2147627130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.UC"
        threat_id = "2147627130"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "http\\shell\\open\\command\\" ascii //weight: 1
        $x_1_3 = "SHGetSpecialFolderLocation" ascii //weight: 1
        $x_1_4 = "We Are HellMakers" ascii //weight: 1
        $x_1_5 = "C:\\WINDOWS\\ud.sys" ascii //weight: 1
        $x_1_6 = "c:\\file.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_UD_2147627187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.UD"
        threat_id = "2147627187"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {23 c8 85 c9 0f 84 ?? ?? 00 00 c7 45 ?? 06 00 00 00 66 8b 55 ?? 66 83 c2 41 0f bf c2 50}  //weight: 2, accuracy: Low
        $x_2_2 = {33 d2 83 7d ?? 05 0f 95 c2 f7 da 66 89 55}  //weight: 2, accuracy: Low
        $x_2_3 = {25 ff 00 00 00 8d 4d ?? 83 f0 01 50 51 ff 15}  //weight: 2, accuracy: Low
        $x_1_4 = "`tunsto/hog" wide //weight: 1
        $x_1_5 = "Z`tunsto\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_XGB_2147627385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.XGB"
        threat_id = "2147627385"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 45 43 59 43 4c 45 52 5c 61 75 74 6f 72 75 6e 65 2e 65 78 65 [0-32] 52 45 43 59 43 4c 45 52 [0-32] 61 75 74 6f 72 75 6e 2e 69 6e 66 [0-32] 5b 61 75 74 6f 72 75 6e 5d [0-32] 6f 70 65 6e 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {73 68 65 6c 6c 5c 6f 70 65 6e 3d 4f 70 65 6e [0-32] 73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 52 45 43 59 43 4c 45 52 5c 61 75 74 6f 72 75 6e 65 2e 65 78 65 [0-32] 2d 4f 70 65 6e 43 75 72 44 69 72}  //weight: 1, accuracy: Low
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_MZ_2147627721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.MZ"
        threat_id = "2147627721"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[AutoRun]" wide //weight: 1
        $x_1_2 = "\\d$\\autorun.inf" wide //weight: 1
        $x_1_3 = "{esc}" wide //weight: 1
        $x_1_4 = "{pause}" wide //weight: 1
        $x_1_5 = "FROM Win32_OperatingSystem" wide //weight: 1
        $x_1_6 = "&content=" wide //weight: 1
        $x_1_7 = "/new.asp?id" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_NA_2147627725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.NA"
        threat_id = "2147627725"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 73 76 68 6f 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 61 75 74 6f 72 75 6e 5d 00}  //weight: 1, accuracy: High
        $x_1_3 = {b8 19 00 00 00 e8 ?? ?? ?? ?? 83 c0 05 99 3b 15 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_YG_2147627751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.YG"
        threat_id = "2147627751"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 5b 51 ff d6 6a 61 8d 95 ?? ?? ?? ?? 52 ff d6 8d 85 ?? ?? ?? ?? 6a 75 50 ff d6 8d 8d ?? ?? ?? ?? bb 08 00 00 00 6a 6e 51}  //weight: 2, accuracy: Low
        $x_2_2 = {0f bf c8 83 f1 ?? 51 ff 15 ?? ?? 40 00 8b d0 8d 4d d8 ff d7 50}  //weight: 2, accuracy: Low
        $x_1_3 = "\\update.vbp" wide //weight: 1
        $x_1_4 = "687474703A2F2F696E6C6F76652E" wide //weight: 1
        $x_1_5 = "3A5C6175746F72756E2E" wide //weight: 1
        $x_1_6 = "77696E68656C7033322E657865" wide //weight: 1
        $x_1_7 = "776C6F2E657865" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_NB_2147627948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.NB"
        threat_id = "2147627948"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "[AutoRun]" ascii //weight: 1
        $x_1_3 = {6f 70 65 6e 3d [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {69 63 6f 6e 3d [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = "C:\\TEMP\\\\autorun.inf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_NE_2147628053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.NE"
        threat_id = "2147628053"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 75 74 6f 72 55 4e 5d 0d 0a 4f 70 65 4e 3d 0d 0a 73 48 65 4c 6c 5c 6f 50 65 4e 5c 43 4f 6d 6d 61 6e 44 3d 52 45 43 59 43 4c 45 52 5c 53 59 53 54 45 4d 2e 2e 5c 52 45 43 59 43 4c 45 52 0d 0a 73 68 65 6c 4c 5c 45 58 70 6c 4f 72 65 5c 43 4f 6d 6d 61 4e 44 3d 52 45 43 59 43 4c 45 52 5c 53 59 53 54 45 4d 2e 2e 5c 52 45 43 59 43 4c 45 52 0d 0a 73 68 65 6c 4c 5c 66 49 6e 44 5c 43 4f 4d 6d 41 6e 44 3d 52 45 43 59 43 4c 45 52 5c 53 59 53 54 45 4d 2e 2e 5c 52 45 43 59 43 4c 45 52}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_UG_2147628106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.UG"
        threat_id = "2147628106"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "TServerSocketBlockMode" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "[autorun]" ascii //weight: 1
        $x_1_5 = ":\\autorun.inf" ascii //weight: 1
        $x_1_6 = "shell\\open=Open" ascii //weight: 1
        $x_1_7 = "Microsoft Corporation. All rights reserved." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_NH_2147628366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.NH"
        threat_id = "2147628366"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00 00 00 ff ff ff ff ?? ?? ?? ?? 5b 61 75 74 6f 72 75 6e 5d}  //weight: 1, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "USB|Infected Drive" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_NI_2147628543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.NI"
        threat_id = "2147628543"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "shell\\find\\Command=RECYCLER\\" ascii //weight: 2
        $x_1_2 = "autorunSource" ascii //weight: 1
        $x_1_3 = "REG.exe ADD \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v ShowSuperHidden /t REG_DWORD /d 0 /f" ascii //weight: 1
        $x_1_4 = "tskill.exe USBGuard" ascii //weight: 1
        $x_1_5 = "H:\\Program Files\\BitDefender" ascii //weight: 1
        $x_1_6 = "attrib.exe +s +r +h \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_NL_2147628687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.NL"
        threat_id = "2147628687"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HdAudio" ascii //weight: 1
        $x_1_2 = "\\ScrCap.jpg" wide //weight: 1
        $x_1_3 = "TCP:*:Enabled:" wide //weight: 1
        $x_1_4 = {5f 00 23 00 57 00 46 00 54 00 23 00 5f 00 00 00 16 00 00 00 24 00 46 00 43 00 52 00 43 00 65 00 72 00 72 00 6f 00 72 00 24 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_UK_2147628816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.UK"
        threat_id = "2147628816"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 3a 57 e8 ?? ?? ?? ?? 83 e8 02 74 17 83 e8 02 74 1f 83 e8 02 75 25}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 07 00 00 00 8b 45 f8 e8 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b 55 fc e8 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 3e}  //weight: 1, accuracy: Low
        $x_1_3 = {5b 41 75 74 6f 52 75 6e 5d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_NO_2147628826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.NO"
        threat_id = "2147628826"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IniWrite ($DskPath & \"\\autorun.inf\", \"autorun\", \"shell\\Autoplay\\Command\"," ascii //weight: 1
        $x_1_2 = "If ProcessExists(\"Explorer.exe\")=0 Then ShellExecute(\"Explorer.exe\", \"\", @WindowsDir,\"open\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_NP_2147628827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.NP"
        threat_id = "2147628827"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TICQ2003Decrypt" ascii //weight: 1
        $x_1_2 = "\\Microsoft\\Network\\Connections\\Pbk\\rasphone.pbk" ascii //weight: 1
        $x_1_3 = "ICQ2003Decrypt1PasswordFound" ascii //weight: 1
        $x_1_4 = ".com.br" ascii //weight: 1
        $x_1_5 = "TCamera" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_NQ_2147628903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.NQ"
        threat_id = "2147628903"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\autorun.inf" wide //weight: 1
        $x_1_2 = "shell\\open=Abrir" wide //weight: 1
        $x_1_3 = "DisableTaskMgr" wide //weight: 1
        $x_1_4 = "Sysyer." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_UM_2147628979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.UM"
        threat_id = "2147628979"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 00 6c 00 34 00 63 00 6b 00 [0-4] 53 00 63 00 30 00 72 00 70 00 69 00 30 00 4e 00}  //weight: 1, accuracy: Low
        $x_1_2 = "{HOME}" wide //weight: 1
        $x_1_3 = "{END}" wide //weight: 1
        $x_1_4 = "Soldier Virus" wide //weight: 1
        $x_1_5 = "[autorun]" wide //weight: 1
        $x_1_6 = "autorun.inf" wide //weight: 1
        $x_1_7 = "Taskkill /im" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_UN_2147628983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.UN"
        threat_id = "2147628983"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "net stop \"Windows Firewall" wide //weight: 1
        $x_1_2 = "[autorun]" wide //weight: 1
        $x_1_3 = "autorun.inf" wide //weight: 1
        $x_1_4 = "\\RECYCLER\\Seting.ini" wide //weight: 1
        $x_1_5 = "\\Recycler\\System Volume Information\\Recycle Bin\\RegSeting" wide //weight: 1
        $x_1_6 = {72 00 65 00 67 00 77 00 72 00 69 00 74 00 65 00 [0-22] 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 20 00 49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_7 = "DisableTaskMgr" wide //weight: 1
        $x_1_8 = "Password" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_NR_2147628997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.NR"
        threat_id = "2147628997"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 55 0c 8a 1e 8a 04 39 02 d1 32 da 32 c2 88 1c 39 88 06 41 4e 3b 4d 08}  //weight: 2, accuracy: High
        $x_1_2 = {3c 61 74 1d 3c 62 74 19 8d 45 fc 50 ff 15 ?? ?? ?? 00 83 f8 02 75 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_VA_2147629408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.VA"
        threat_id = "2147629408"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".nurotua\\:" wide //weight: 1
        $x_1_2 = "\\swodniW\\tfosorciM\\" wide //weight: 1
        $x_1_3 = "__vbaFileOpen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_RY_2147629789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.RY"
        threat_id = "2147629789"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\autorun.inf" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "localip=127.0.0.1&compname=" ascii //weight: 1
        $x_1_4 = "system32\\drivers\\etc\\svchost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_UO_2147629816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.UO"
        threat_id = "2147629816"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "c2hlbGxleGVjdXRlPWV4cGxvcmVkcml2ZS5leGU=" wide //weight: 2
        $x_2_2 = "c2hlbGxcb3Blblxjb21tYW5kPWV4cGxvcmVkcml2ZS5leGU=" wide //weight: 2
        $x_2_3 = "[USB]: Infected drive:" wide //weight: 2
        $x_1_4 = {57 00 32 00 46 00 31 00 64 00 47 00 39 00 79 00 64 00 57 00 35 00 64 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_VC_2147630382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.VC"
        threat_id = "2147630382"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Autorun]" wide //weight: 1
        $x_1_2 = "*Program(Virus) ini hanya" wide //weight: 1
        $x_1_3 = "Shell\\auto\\command=" wide //weight: 1
        $x_1_4 = "and all Indonesian VM/VC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_VG_2147630452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.VG"
        threat_id = "2147630452"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"61336552779482\"" ascii //weight: 1
        $x_1_2 = "\"\\Yahoo! video chat.exe\")" ascii //weight: 1
        $x_1_3 = ".writeline \"Open=2779\\SCANNING.EXE\"" ascii //weight: 1
        $x_1_4 = ".FileExists(\"c:\\2779\\Desktop.ini\")" ascii //weight: 1
        $x_1_5 = ".regwrite \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\DTCI\"" ascii //weight: 1
        $x_1_6 = ".writeline \"CLSID={645FF040-5081-101B-9F08-00AA002F954E}\"" ascii //weight: 1
        $x_1_7 = ".writeline \"[Autorun]\"" ascii //weight: 1
        $x_1_8 = "getobject(\"winmgmts:\"&\"{impersonationLevel=impersonate}!\\\\\"" ascii //weight: 1
        $x_1_9 = "getobject(\"WinNT://./\"&i&\",user\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Worm_Win32_Autorun_VR_2147630693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.VR"
        threat_id = "2147630693"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://vipp.sitegoogle.cn/superj.asp" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options/" ascii //weight: 1
        $x_1_4 = "KAVPFW.exe" ascii //weight: 1
        $x_1_5 = "RavMon.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_VQ_2147630701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.VQ"
        threat_id = "2147630701"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\autorun.inf" ascii //weight: 1
        $x_1_2 = "[autorun]" ascii //weight: 1
        $x_1_3 = "[.ShellClassInfo]" ascii //weight: 1
        $x_1_4 = "APPLICATION : KEYLOGGER" ascii //weight: 1
        $x_1_5 = "setLoginSavingEnabled(aLogin.hostname, false);" ascii //weight: 1
        $x_1_6 = "showLoginNotification(aNotifyBox, \"password-save\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_WA_2147630767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.WA"
        threat_id = "2147630767"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 02 74 1a 56 e8 ?? ?? ff ff 83 f8 04 74 0f 56 e8 ?? ?? ff ff 83 f8 03 0f 85 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {43 80 fb 7b 0f 85 ?? ff ff ff 6a 04 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_WB_2147630775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.WB"
        threat_id = "2147630775"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\update.vbp" wide //weight: 1
        $x_1_2 = ":\\autorun." wide //weight: 1
        $x_1_3 = "Microsoft Corporation. Reservados todos los derechos." wide //weight: 1
        $x_1_4 = "tmrCentinela" ascii //weight: 1
        $x_1_5 = "_C:\\Windows\\system32\\ieframe.oca" ascii //weight: 1
        $x_1_6 = "tmrEliminar" ascii //weight: 1
        $x_1_7 = "inicio" ascii //weight: 1
        $x_1_8 = "Crear_Autorun" ascii //weight: 1
        $x_1_9 = "Copiar_Autorun" ascii //weight: 1
        $x_1_10 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_WE_2147631288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.WE"
        threat_id = "2147631288"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "# Por ejemplo:" ascii //weight: 1
        $x_1_2 = "127.0.0.1 kaspersky-labs.com " ascii //weight: 1
        $x_1_3 = "shell\\open=Open" ascii //weight: 1
        $x_1_4 = "killermsconfig" ascii //weight: 1
        $x_1_5 = "C:\\WINDOWS\\SYSTEM32\\MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_WL_2147631566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.WL"
        threat_id = "2147631566"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 6e 77 6c 6e 25 5b 61 75 74 6f 72 75 6e 5d 60 6e 6f 70 65 6e 3d 43 4f 4e 54 52 4f 4c 5c 41 75 74 6f 52 75 6e 2e 65 78 65 20 a0 60 6e 73 68 65 6c 6c 5c 4f 70 65 6e 3d 26 4f 70 65 6e 60 6e 73 68 65 6c 6c 5c 4f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 43 4f 4e 54 52 4f 4c 5c 41 75 74 6f 52 75 6e 2e 65 78 65 20 a0}  //weight: 1, accuracy: High
        $x_1_2 = "IniWrite, {7007acc7-3202-11d1-aad2-00805fc1270e} , %a_programfiles%\\WebSecurity\\Desktop.ini, .ShellClassInfo, CLSID" ascii //weight: 1
        $x_1_3 = "urldownloadtofile, http://microsoft.com/windows/, winupdchk%rnn%.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_WN_2147631785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.WN"
        threat_id = "2147631785"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HDDFile.com" wide //weight: 1
        $x_1_2 = "autorun.inf" wide //weight: 1
        $x_1_3 = "[autorun]" wide //weight: 1
        $x_2_4 = "\\Hacking Tools\\KEYLOGGER PROJECT" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_WS_2147632382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.WS"
        threat_id = "2147632382"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 89 45 e4 68 ?? ?? ?? ?? 8b 4d e4 51 e8 ?? ?? ?? ?? 83 c4 08 8b f4 6a 00 6a 00 6a 02 6a 00 6a 00 68 00 00 00 40 8b 55 e4 52 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "c:\\Windows\\System\\msdumprep.exe %1" ascii //weight: 1
        $x_1_3 = "[AutoRun]" wide //weight: 1
        $x_1_4 = "open=msdumprep.exe" wide //weight: 1
        $x_1_5 = "shell\\explore\\Command=msdumprep.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_WZ_2147632654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.WZ"
        threat_id = "2147632654"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f4 64 eb 6e 18 ff b3 f4 01 eb ab fb e6}  //weight: 1, accuracy: High
        $x_1_2 = {f5 69 00 00 00 04 ?? fe 0a ?? ?? ?? ?? 04 ?? fe fb ef ?? fe f5 6e 00 00 00 04 84 fe 0a ?? ?? ?? ?? 04 ?? fe fb ef ?? fe f5 66 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_XE_2147632879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.XE"
        threat_id = "2147632879"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5b 61 75 74 6f 72 75 6e 5d 0d 0a 73 68 65 6c 6c 65 78 65 63 75 74 65 3d 22 77 69 6e 73 79 73 2e 65 78 65 22 0d 0a 55 73 65 41 75 74 6f 50 6c 61 79 3d 31 00}  //weight: 2, accuracy: High
        $x_2_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 73 00 79 00 73 00 69 00 6e 00 66 00 44 00 61 00 74 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_1_3 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 53 00 52 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {4e 00 6f 00 4d 00 61 00 6e 00 61 00 67 00 65 00 4d 00 79 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 56 00 65 00 72 00 62 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 54 00 6f 00 6f 00 6c 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 41 00 6e 00 74 00 69 00 44 00 6f 00 64 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_XF_2147632881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.XF"
        threat_id = "2147632881"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://msn.com" ascii //weight: 1
        $x_1_2 = "shellexecute=autorun.exe" ascii //weight: 1
        $x_1_3 = {61 73 64 66 5f 31 00 69 6e 65 74 5f 31 00 75 70 64 74 5f 31}  //weight: 1, accuracy: High
        $x_1_4 = "Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_XI_2147632955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.XI"
        threat_id = "2147632955"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fni.nurotua" wide //weight: 1
        $x_1_2 = "]nurotuA[" wide //weight: 1
        $x_1_3 = {28 14 ff 61 00 04 48 ff 28 24 ff 7a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_XM_2147633028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.XM"
        threat_id = "2147633028"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\autorun.inf" wide //weight: 1
        $x_1_2 = "& move *.doc" wide //weight: 1
        $x_1_3 = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR\\Enum" wide //weight: 1
        $x_1_4 = "Bow.vbp" wide //weight: 1
        $x_1_5 = "ShowSuperHidden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_Win32_Autorun_YN_2147633508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.YN"
        threat_id = "2147633508"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\TempIEData.exe" wide //weight: 1
        $x_1_2 = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" wide //weight: 1
        $x_1_3 = "Shell_TrayWnd" wide //weight: 1
        $x_1_4 = "\\autorun.inf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_YR_2147634360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.YR"
        threat_id = "2147634360"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 bd 5c fe ff ff 02 0f 94 c1 f7 d9 66 85 c9 0f 84}  //weight: 1, accuracy: High
        $x_1_2 = {46 75 63 6b 41 6c 6c 00 46 75 63 6b 45 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "autorun.inf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_YU_2147635728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.YU"
        threat_id = "2147635728"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[autorun]" wide //weight: 1
        $x_1_2 = "*-*REMOVIVEL&-&" wide //weight: 1
        $x_1_3 = "\\systen.exe" wide //weight: 1
        $x_1_4 = "\\Software\\Norton\\" wide //weight: 1
        $x_1_5 = "Firewall Desabilitado" ascii //weight: 1
        $x_1_6 = "Arquivo executado!" ascii //weight: 1
        $x_1_7 = "Problemas ao iniciar Keylogger" ascii //weight: 1
        $x_1_8 = "Processo terminado..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Worm_Win32_Autorun_YV_2147635740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.YV"
        threat_id = "2147635740"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "del C:\\Windows\\Boot.bat" ascii //weight: 2
        $x_2_2 = "shell\\Auto\\Command=...\\" ascii //weight: 2
        $x_1_3 = "SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile" ascii //weight: 1
        $x_1_4 = "IdTCPServer" ascii //weight: 1
        $x_3_5 = "Explorer.exe C:\\Windows\\System32\\ctfmon_.exe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_YZ_2147636069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.YZ"
        threat_id = "2147636069"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff 75 94 e8 ?? ?? ?? ?? 89 45 98 83 7d 98 02 0f 85 ?? ?? ?? ?? 66 c7 45 bc 44 00 8d 45 ec e8}  //weight: 10, accuracy: Low
        $x_10_2 = "GetLogicalDriveStringsA" ascii //weight: 10
        $x_10_3 = {5b 41 75 74 6f 52 75 6e 5d 0a 73 68 65 6c 6c 65 78 65 63 75 74 65 3d}  //weight: 10, accuracy: High
        $x_1_4 = "\\default.inf" ascii //weight: 1
        $x_1_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 00 48 69 64 64 65 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_ZC_2147636407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ZC"
        threat_id = "2147636407"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!logout" ascii //weight: 1
        $x_1_2 = "Downloading/Executing..." ascii //weight: 1
        $x_1_3 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3" ascii //weight: 1
        $x_1_4 = "autorun.inf" ascii //weight: 1
        $x_2_5 = "%appdata%\\svchost.exe" ascii //weight: 2
        $x_2_6 = "Infected Removable Drive.." ascii //weight: 2
        $x_2_7 = {8a 04 0b f6 d0 88 01 8b c7 46 41 8d 78 01 8a 10 40 84 d2 75 f9 2b c7 3b f0 72 e2 8b 4d 08 5b 5f 88 14 0e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_ZE_2147636468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ZE"
        threat_id = "2147636468"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Polymorphic_usb_load" ascii //weight: 3
        $x_2_2 = "SELECT * FROM moz_logins;" wide //weight: 2
        $x_3_3 = ".exe\" %%t\\e$\\shared\\debug.exe" wide //weight: 3
        $x_2_4 = "/c echo [autorun] >>" wide //weight: 2
        $x_1_5 = "\\morpheus\\my shared folder\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_ZG_2147636517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ZG"
        threat_id = "2147636517"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "usbspread" ascii //weight: 3
        $x_2_2 = "antizonealarm" ascii //weight: 2
        $x_2_3 = "antisandboxie" ascii //weight: 2
        $x_2_4 = "get_FirePassword" ascii //weight: 2
        $x_2_5 = "AntiParallelsDesktop" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_ZH_2147636669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ZH"
        threat_id = "2147636669"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 fa 8b 34 00 ff b5 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = "Windows Update" ascii //weight: 1
        $x_1_3 = "Kaspersky Update" ascii //weight: 1
        $x_1_4 = "RtlDecompressBuffer" ascii //weight: 1
        $x_1_5 = "LockResource" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "ResumeThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_ZH_2147636669_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ZH"
        threat_id = "2147636669"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sxchost.exe" ascii //weight: 2
        $x_2_2 = "icon=\"%SystemRoot%\\system32\\SHELL32.dll,8\"" ascii //weight: 2
        $x_1_3 = "c:\\windows\\system32\\drivers\\etc\\hosts" ascii //weight: 1
        $x_3_4 = "http://masung.selfip.biz/" ascii //weight: 3
        $x_2_5 = "shell\\explore\\Command=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_ZH_2147636669_2
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ZH"
        threat_id = "2147636669"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {46 69 6c 65 4e 61 6d 65 41 63 74 75 61 6c [0-32] 46 69 72 73 74 49 6e 73 74 61 6c 6c [0-16] 64 64 6f 73 65 72 [0-16] 55 53 42}  //weight: 10, accuracy: Low
        $x_1_2 = "[autorun]" ascii //weight: 1
        $x_1_3 = "shell=verb" ascii //weight: 1
        $x_1_4 = "action=Open folder to view files" ascii //weight: 1
        $x_1_5 = "icon=%SystemRoot%\\system32\\SHELL32.dll,4" ascii //weight: 1
        $x_1_6 = "USB||*||Infected Drive " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_ZI_2147636750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ZI"
        threat_id = "2147636750"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\autorun.inf" ascii //weight: 1
        $x_2_2 = "Testing.exe" ascii //weight: 2
        $x_1_3 = "Policies\\System\\DisableRegistryTools" ascii //weight: 1
        $x_1_4 = "winmgmts:\\\\.\\root\\default:SystemRestore" ascii //weight: 1
        $x_2_5 = "ion\\Policies\\System /v DisableTaskMgr /t REG_DWORD" ascii //weight: 2
        $x_2_6 = "rapidshare.com/cgi-bin/upload.cgi?rsuploadid=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_ZJ_2147636995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ZJ"
        threat_id = "2147636995"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 10 99 f7 7d ?? 50}  //weight: 1, accuracy: Low
        $x_1_2 = "BF50AC63-19DA-487E-AD4A-0B452D823B59" ascii //weight: 1
        $x_2_3 = {6f 70 65 6e 3d 00 00 00 52 75 6e 2e 69 6e 66}  //weight: 2, accuracy: High
        $x_2_4 = {63 79 63 00 63 3a 5c 72 65}  //weight: 2, accuracy: High
        $x_1_5 = "sou.com/bmw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_ZJ_2147636995_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ZJ"
        threat_id = "2147636995"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "VIRTUAL BOX SUCK" ascii //weight: 3
        $x_3_2 = "Virtual box suck lol" ascii //weight: 3
        $x_2_3 = "LiveUSB.exe" ascii //weight: 2
        $x_2_4 = "Adobe Reader Updater" ascii //weight: 2
        $x_1_5 = "shellexecute=%s" ascii //weight: 1
        $x_1_6 = "[autorun]" ascii //weight: 1
        $x_3_7 = "%sautorun.inf" ascii //weight: 3
        $x_3_8 = "rundli32.exe" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_ZW_2147639038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ZW"
        threat_id = "2147639038"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d4 cb d0 d0 ca b1 b3 f6 b4 ed 21}  //weight: 1, accuracy: High
        $x_1_2 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 00 5b 61 75 74 6f 72 75 6e 5d 0d 0a 6f 70 65 6e 3d 00 61 75 74 6f 72 75 6e 2e 69 6e 66 00 62 61 6b 2e 62 61 6b 00 5c 31 2e 69 63 6f 00}  //weight: 1, accuracy: High
        $x_1_3 = {4e 6f 53 65 74 46 6f 6c 64 65 72 73 3c 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72}  //weight: 1, accuracy: Low
        $x_1_4 = {44 69 73 61 62 6c 65 43 4d 44 2b 00 53 6f 66 74 77 61 72 65 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d}  //weight: 1, accuracy: Low
        $x_1_5 = {4e 6f 46 69 6c 65 4d 65 6e 75 3c 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AAA_2147639326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AAA"
        threat_id = "2147639326"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Autorun]" wide //weight: 1
        $x_1_2 = "Label=Unidad de disco" wide //weight: 1
        $x_1_3 = "Foto Capturada correctamente" wide //weight: 1
        $x_1_4 = "c:\\windows\\system32\\suchost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AAI_2147640328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AAI"
        threat_id = "2147640328"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DDoS, type stopflood to stop" ascii //weight: 1
        $x_1_2 = "%sautorun.inf" ascii //weight: 1
        $x_1_3 = "netsh firewall set opmode mode=disable profile=all" ascii //weight: 1
        $x_1_4 = "ICWorm\\Release\\ICWorm.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AAK_2147640510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AAK"
        threat_id = "2147640510"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\TrojanDetector.exe\\Debugger" ascii //weight: 2
        $x_2_2 = "chtdll.dll" ascii //weight: 2
        $x_1_3 = "gg_file" ascii //weight: 1
        $x_1_4 = "net.exe stop " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AAN_2147640750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AAN"
        threat_id = "2147640750"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill -f -im explorer.exe" ascii //weight: 1
        $x_1_2 = "start/max http://saibatudomesmo.blogspot.com/" ascii //weight: 1
        $x_1_3 = "s\\System\" \"DisableTaskMgr\" \"1\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_ABJ_2147642254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ABJ"
        threat_id = "2147642254"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Archivos de programa\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 1
        $x_1_2 = "[autorun]" ascii //weight: 1
        $x_1_3 = "shell\\open\\Command=autorun.exe" ascii //weight: 1
        $x_1_4 = ": L3Ts kiLL BILL ;)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_ABO_2147643105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ABO"
        threat_id = "2147643105"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 04 37 80 38 e9 74 ?? 50 e8 ?? ?? ?? ?? 85 c0 59 7d ?? 33 c0 5f 5e 5b c9 c3 8b 48 01 8d 7c 01 05 33 c0 33 f6 03 f0 83 fe 06}  //weight: 1, accuracy: Low
        $x_1_2 = "[autorun]" ascii //weight: 1
        $x_1_3 = "shell\\Explore\\Command=%S" ascii //weight: 1
        $x_1_4 = "PROCESS_MT_" wide //weight: 1
        $x_1_5 = "svrwsc.exe" wide //weight: 1
        $x_1_6 = "autorun.inf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Worm_Win32_Autorun_ABP_2147643193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ABP"
        threat_id = "2147643193"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\WINDOWS\\windowsxp.exe" ascii //weight: 1
        $x_1_2 = "\"C:\\WINDOWS\\system\\csrss.exe\" /para" ascii //weight: 1
        $x_1_3 = "C:\\RECYCLER\\S-1-5-21-1482476501-1644491937-682003330-1013\\smartmgr.exe" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\{28ABC5C0-4FCB-11CF-AAX5-81CX1C635612}" ascii //weight: 1
        $x_1_5 = "autorun.inf" ascii //weight: 1
        $x_1_6 = "shell\\explore\\Command=windowsxp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_ABR_2147643672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ABR"
        threat_id = "2147643672"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 74 1b 83 f8 01 74 16 83 f8 05 74 11 83 f8 06 74 0c 83 f8 02 75 07 53 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = "action=Explore USB-drive files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_ABS_2147643806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ABS"
        threat_id = "2147643806"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 69 6c 65 20 74 6f [0-4] 20 72 6f 6d 6f 74 65}  //weight: 1, accuracy: Low
        $x_1_2 = "P2PCMD.hello!" ascii //weight: 1
        $x_1_3 = "P2PCMD.Brcast" ascii //weight: 1
        $x_1_4 = "netware work " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_XGK_2147644196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.XGK"
        threat_id = "2147644196"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "C:\\windows\\usr\\svchost.exe" ascii //weight: 3
        $x_1_2 = "C:\\windows\\usr\\server.exe" ascii //weight: 1
        $x_1_3 = "C:\\windows\\usr\\explorer.exe" ascii //weight: 1
        $x_1_4 = "\\autorun.inf" ascii //weight: 1
        $x_1_5 = "attrib +H %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_ACE_2147645361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ACE"
        threat_id = "2147645361"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 70 72 65 61 64 [0-2] 64 72 69 76 65 [0-2] 53 65 74 41 75 74 6f 72 75 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "\\autorun.inf" wide //weight: 1
        $x_1_3 = "Open = LgOACX.exe" wide //weight: 1
        $x_1_4 = "%%t\\IPC$\\debug.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_XEK_2147646392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.XEK"
        threat_id = "2147646392"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\WinSysFix_1.5.vbp" wide //weight: 1
        $x_1_2 = "\\syssh32.dll" wide //weight: 1
        $x_1_3 = "\\$Tmp~12026\\" wide //weight: 1
        $x_1_4 = "SVCHOSI.EXE" wide //weight: 1
        $x_1_5 = "2026\\2045\\ashsvc.exe" wide //weight: 1
        $x_1_6 = "Win_Sys_Fix_2010" wide //weight: 1
        $x_1_7 = "ShElLexEcUte=" wide //weight: 1
        $x_1_8 = "sHeLl\\OpEn\\CoMmAnD" wide //weight: 1
        $x_1_9 = "ShElL\\OpeN\\DeFaUlT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Worm_Win32_Autorun_ACM_2147646502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ACM"
        threat_id = "2147646502"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "GetHashCode" ascii //weight: 10
        $x_1_2 = "Q3Jpc2lzLmV4ZQ==" wide //weight: 1
        $x_1_3 = "YXV0b3J1bi5pbmY=" wide //weight: 1
        $x_1_4 = "XFR3YWluLmRsbA==" wide //weight: 1
        $x_1_5 = "FlashPlayer.exe" wide //weight: 1
        $x_1_6 = "c2V0dXAuZXhl" wide //weight: 1
        $x_1_7 = "XGFjbHVpLmRsbA==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_ACN_2147646684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ACN"
        threat_id = "2147646684"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Autorun.inf" ascii //weight: 10
        $x_2_2 = "%s VirUs \"\" \"lol\" :%s" ascii //weight: 2
        $x_1_3 = "taskkill /IM %s" ascii //weight: 1
        $x_1_4 = "%s\\removeMe%i%i%i%i.bat" ascii //weight: 1
        $x_1_5 = "PRIVMSG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_ACT_2147647395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ACT"
        threat_id = "2147647395"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "80"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Support to windows system services." ascii //weight: 10
        $x_10_2 = ".\\...\\Ugos.com" ascii //weight: 10
        $x_10_3 = {41 4e 41 48 54 41 52 00 44 42 47 53}  //weight: 10, accuracy: High
        $x_10_4 = {3a 5c 52 65 63 79 63 6c 65 64 00 00 78 63 6f 70 79 2e 69 6e 69}  //weight: 10, accuracy: High
        $x_10_5 = "USBDRIVER" ascii //weight: 10
        $x_5_6 = {73 68 65 6c 6c 5c [0-22] 5c 43 6f 6d 6d 61 6e 64 3d 25 73}  //weight: 5, accuracy: Low
        $x_5_7 = "shellexecute=%s" ascii //weight: 5
        $x_5_8 = "[autorun]" ascii //weight: 5
        $x_5_9 = "autorun.inf" ascii //weight: 5
        $x_5_10 = "McaFee virus detect program." ascii //weight: 5
        $x_5_11 = ":\\Program Files\\Network Associates\\VirusScan\\McaUpdate.exe" ascii //weight: 5
        $x_1_12 = "cmd /c set user >>" ascii //weight: 1
        $x_1_13 = "cmd /c net view /domain >>" ascii //weight: 1
        $x_1_14 = "cmd /c systeminfo >>" ascii //weight: 1
        $x_1_15 = "cmd /c ipconfig/all >>" ascii //weight: 1
        $x_1_16 = ":\\Program Files\\Common Files\\System\\" ascii //weight: 1
        $x_1_17 = "%d-%02d-%02d-%02d-%02d" ascii //weight: 1
        $x_1_18 = "....\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 5 of ($x_5_*) and 5 of ($x_1_*))) or
            ((5 of ($x_10_*) and 6 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_ACU_2147647571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ACU"
        threat_id = "2147647571"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 45 f7 80 7d f7 5b 0f 85 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "netsh firewall set opmode disable" ascii //weight: 1
        $x_1_3 = ":\\autorun.inf" ascii //weight: 1
        $x_1_4 = {8d 85 b4 fe ff ff 50 8b 45 fc e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 45 f4 83 7d f4 ff 74 0f c6 45 fb 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_ACW_2147647744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ACW"
        threat_id = "2147647744"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "the shade doesn't want you death" wide //weight: 1
        $x_1_2 = {52 00 45 00 47 00 20 00 41 00 44 00 44 00 20 00 48 00 4b 00 4c 00 4d 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 20 00 2f 00 66 00 20 00 2f 00 76 00 20 00 57 00 69 00 6e 00 53 00 69 00 78 00 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 53 00 5a 00 20 00 2f 00 64 00 20 00 22 00 00 00 00 00 18 00 00 00 53 00 56 00 43 00 48 00 4f 00 53 00 49 00 2e 00 45 00 58 00 45 00 22 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 00 75 00 54 00 6f 00 72 00 55 00 6e 00 5d 00 00 00 00 00 1a 00 00 00 53 00 68 00 45 00 6c 00 4c 00 65 00 78 00 45 00 63 00 55 00 74 00 65 00 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_ADL_2147650721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ADL"
        threat_id = "2147650721"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 15 48 f0 40 00 [0-2] a3 04 10 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 00 90 52 90 5a}  //weight: 1, accuracy: High
        $x_1_3 = {bb 00 10 40 00 89 db 52 90 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_ADS_2147651678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ADS"
        threat_id = "2147651678"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 15 48 00 41 00 a3 04 10 40 00}  //weight: 1, accuracy: High
        $x_1_2 = {eb 00 eb 00 90 88 c0}  //weight: 1, accuracy: High
        $x_1_3 = {bb 00 10 40 00 89 db 52 90 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_ADU_2147651681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ADU"
        threat_id = "2147651681"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff 15 48 f0 40 00 [0-2] a3 04 10 40 00}  //weight: 10, accuracy: Low
        $x_10_2 = {eb 00 90 86 d2 90 89 db}  //weight: 10, accuracy: High
        $x_1_3 = {bb 00 10 40 00 89 db 52 90 5a}  //weight: 1, accuracy: High
        $x_1_4 = {bb 00 10 40 00 89 db cd 03 90 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_ADZ_2147652561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.ADZ"
        threat_id = "2147652561"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "userandpc=%s&admin=%s&os=%s&hwid=%s&ownerid=%s" ascii //weight: 2
        $x_1_2 = "\\Application Data\\gpresultl.exe" ascii //weight: 1
        $x_1_3 = {53 6f 66 74 77 61 72 65 5c 48 53 65 74 74 69 6e 67 5c 00}  //weight: 1, accuracy: High
        $x_1_4 = {69 64 7c 00}  //weight: 1, accuracy: High
        $x_1_5 = {44 4c 7c 00}  //weight: 1, accuracy: High
        $x_1_6 = {55 50 7c 00}  //weight: 1, accuracy: High
        $x_1_7 = {56 49 7c 00}  //weight: 1, accuracy: High
        $x_1_8 = {55 4e 7c 00}  //weight: 1, accuracy: High
        $x_1_9 = "zeroxcode.net/herpnet/" ascii //weight: 1
        $x_1_10 = {61 75 74 6f 72 75 6e 2e 69 6e 66 00 6a 6b 70 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_11 = {48 65 72 70 65 73 4d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_1_*))) or
            ((1 of ($x_2_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_AEA_2147652816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AEA"
        threat_id = "2147652816"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Windows;Program*" ascii //weight: 1
        $x_1_2 = "shell\\open\\Default=1" ascii //weight: 1
        $x_1_3 = "shell\\open\\Command=syskernel.exe" ascii //weight: 1
        $x_1_4 = {3a 5c 4e 65 77 20 46 6f 6c 64 65 72 [0-1] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = ":\\Autorun.inf" ascii //weight: 1
        $x_1_6 = "[autorun]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AEB_2147652844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AEB"
        threat_id = "2147652844"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "winmgmts:\\\\.\\root\\SecurityCenter" wide //weight: 1
        $x_1_2 = {5b 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 [0-16] 6f 00 70 00 65 00 6e 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {7b 00 44 00 65 00 6c 00 65 00 74 00 65 00 7d 00 [0-16] 7b 00 42 00 61 00 63 00 6b 00 7d 00 [0-16] 7b 00 54 00 61 00 62 00 7d 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\LimeWire\\Shared\\" wide //weight: 1
        $x_1_5 = "nuR\\noisreVtnerruC\\swodniW\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AEC_2147652877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AEC"
        threat_id = "2147652877"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%A_LoopField%:\\AutoRun.inf" ascii //weight: 1
        $x_1_2 = "open=facebook_photo.exe" ascii //weight: 1
        $x_1_3 = "%A_WinDir%\\encoder.txt" ascii //weight: 1
        $x_1_4 = "MSInfo\\Recycled.scr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AED_2147652879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.gen!AED"
        threat_id = "2147652879"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 55 54 4f 52 55 4e 2e 49 4e 46 00 5b 41 55 54 4f 52 55 4e 5d}  //weight: 1, accuracy: High
        $x_1_2 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 00 48 69 70 70 6f 70 6f 74 61 6d 75 73}  //weight: 1, accuracy: High
        $x_1_3 = {46 72 61 6d 65 57 6f 72 6b 00 48 69 64 64 65 6e 00 53 68 6f 77 53 75 70 65 72 48 69 64 64 65 6e 00 53 75 70 65 72 48 69 64 64 65 6e}  //weight: 1, accuracy: High
        $x_2_4 = {51 b1 08 c1 c0 04 50 24 0f 04 f6 18 e4 80 e4 07 00 e0 04 3a aa 58 fe c9 75 e9 59 c3}  //weight: 2, accuracy: High
        $x_2_5 = {8b 06 3d 36 36 36 36 0f 84 ?? ?? ?? ?? 3d 37 37 37 37 0f 84 ?? ?? ?? ?? 3d 39 39 39 39 0f 84 ?? ?? ?? ?? 46 8a 06 84 c0 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AEG_2147653140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AEG"
        threat_id = "2147653140"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Policies\\Explorer\\DisallowRun" ascii //weight: 1
        $x_1_2 = "\\Menu Start\\Programy\\Autostart\\Start.exe" ascii //weight: 1
        $x_1_3 = "taskkill /FI \"USERNAME eq " ascii //weight: 1
        $x_1_4 = "/im svchost.exe /f" ascii //weight: 1
        $x_1_5 = "shellAutoruncommand=start.exe" ascii //weight: 1
        $x_1_6 = "autorun.inf" ascii //weight: 1
        $x_1_7 = "[autorun]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AEH_2147653189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AEH"
        threat_id = "2147653189"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\LimeWire\\LimeWire.exe" wide //weight: 1
        $x_1_2 = "\\Shareaza\\Shareaza.exe" wide //weight: 1
        $x_1_3 = "\\Ares\\Ares.exe" wide //weight: 1
        $x_1_4 = "\\micka.exe" wide //weight: 1
        $x_1_5 = "autorun.inf" wide //weight: 1
        $x_1_6 = "[autorun]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AEK_2147653229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AEK"
        threat_id = "2147653229"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "c:\\autorun.inf" wide //weight: 1
        $x_1_2 = "[autorun]" wide //weight: 1
        $x_1_3 = "shutdown /f" wide //weight: 1
        $x_1_4 = {5c 00 50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 22 00 20 00 [0-16] 20 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 20 00 2f 00 64 00 20 00 31 00}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 00 50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 22 00 20 00 [0-37] 20 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 74 00 6f 00 6f 00 6c 00 73 00 20 00 2f 00 64 00 20 00 31 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AEL_2147653269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AEL"
        threat_id = "2147653269"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 41 75 74 6f 52 75 6e 5d [0-48] 73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 73 76 63 68 6f 73 74 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "AutoRun.inf" ascii //weight: 1
        $x_3_3 = "360se_Frame" ascii //weight: 3
        $x_6_4 = "c:\\TSTP\\winlogon.exe" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_AEM_2147653296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AEM"
        threat_id = "2147653296"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "autorun.inf" wide //weight: 1
        $x_1_2 = "UACBypass" wide //weight: 1
        $x_1_3 = "USBSpread" wide //weight: 1
        $x_2_4 = "configuration/sendpassword" wide //weight: 2
        $x_2_5 = "Windows 7 Crack" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_AEO_2147653599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AEO"
        threat_id = "2147653599"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "KeyLogger" ascii //weight: 1
        $x_1_2 = {61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 [0-16] 5b 00 61 00 75 00 74 00 6f 00 52 00 75 00 6e 00 5d 00 [0-16] 4f 00 50 00 45 00 4e 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_3 = "/extract.php?x=" wide //weight: 1
        $x_1_4 = {3a 00 5c 00 2a 00 2e 00 2a 00 [0-16] 3a 00 5c 00 4e 00 65 00 77 00 20 00 46 00 6f 00 6c 00 64 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_5 = {26 00 75 00 6e 00 3d 00 [0-8] 26 00 65 00 78 00 65 00 3d 00 [0-8] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AEQ_2147653754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AEQ"
        threat_id = "2147653754"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "\"daojiaoshihao\" = \"C:\\\\WINDOWS\\\\system32\\\\Dg_Kun.exe\"" ascii //weight: 6
        $x_7_2 = "http://wukuen520.web113.hzfwq.com/daojiaoshihao/Dg_Kun-doc.exe" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AER_2147653824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AER"
        threat_id = "2147653824"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shell\\explore=" wide //weight: 1
        $x_2_2 = "SOFTWARE\\Classes\\Drive\\shell\\open\\command" wide //weight: 2
        $x_3_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL" wide //weight: 3
        $x_3_4 = "\\autorun.inf" wide //weight: 3
        $x_4_5 = "\\Recycled.{645FF040-5081-101B-9F08-00AA002F954E}" wide //weight: 4
        $x_4_6 = "regfile\\shell\\open\\command" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AET_2147654041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AET"
        threat_id = "2147654041"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "USBDisk" wide //weight: 1
        $x_1_2 = "%s://autorun.exe" ascii //weight: 1
        $x_2_3 = "%s://autorun.inf" ascii //weight: 2
        $x_3_4 = {8a 1c 37 32 d2 8d 4d ed c7 45 08 08 00 00 00 84 59 ff 74 04 0a 11 eb 06 8a 01 f6 d0 22 d0 41 41 ff 4d 08 75 ea 88 14 37 47 3b 7d fc 7c d2}  //weight: 3, accuracy: High
        $x_3_5 = {80 e3 7f eb 1e f6 04 31 40 74 05 80 cb 20 eb 13 80 e3 df eb 0e f6 04 31 20 74 05 80 cb 40 eb 03 80 e3 bf 99 2b c2 d1 f8 85 c0 0f 8f 45 ff ff ff 88 1c 31 41 3b cf 0f 8c 32 ff ff ff}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_AEU_2147654250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AEU"
        threat_id = "2147654250"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 68 65 6c 6c 2f 65 78 70 6c 6f 72 65 2f 63 6f 6d 6d 61 6e 64 3d [0-11] 61 75 74 6f 72 75 6e 2e 69 6e 66}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 [0-12] 5c 73 76 63 68 6f 73 74 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d [0-11] 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72}  //weight: 1, accuracy: Low
        $x_1_4 = "smtp.mail.yahoo.co.uk" ascii //weight: 1
        $x_1_5 = "[Ctrl]" ascii //weight: 1
        $x_1_6 = "[Esc]" ascii //weight: 1
        $x_1_7 = "kill enemay" ascii //weight: 1
        $x_1_8 = "\\NewVerSion.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_AEW_2147654874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AEW"
        threat_id = "2147654874"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "welcometoooty" wide //weight: 1
        $x_1_2 = {73 00 76 00 63 00 68 00 30 00 73 00 74 00 2e 00 65 00 78 00 65 00 ?? ?? 6c 00 69 00 6e 00 6b 00 73 00 2e 00 6c 00 6e 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_3 = {4e 00 65 00 77 00 46 00 6f 00 6c 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00 ?? ?? 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_UL_2147655464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.UL"
        threat_id = "2147655464"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "My Videos.exe" wide //weight: 1
        $x_1_2 = "M:\\autorun.inf" wide //weight: 1
        $x_1_3 = "explorer.exe-autorun" wide //weight: 1
        $x_1_4 = "CurrentVersion\\Run\\autorun" wide //weight: 1
        $x_1_5 = {78 63 6f 70 79 [0-16] 2e 65 78 65 [0-5] 25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 44 65 73 6b 74 6f 70 5c}  //weight: 1, accuracy: Low
        $x_1_6 = {6d 6b 64 69 72 [0-5] 25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 44 65 73 6b 74 6f 70 5c}  //weight: 1, accuracy: Low
        $x_1_7 = "[autorun]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AEY_2147656123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AEY"
        threat_id = "2147656123"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MD C:\\RECYCLER\\S-1-5-~1\\BDV\\\"Welcome at BD Virus\"" ascii //weight: 1
        $x_1_2 = "for %%r in (d;e;f;g;h;i;j;k;l;m;n;o;p;q;r;s;t;u;v)" ascii //weight: 1
        $x_1_3 = "attrib +s +h +r +a C:\\RECYCLER\\S-1-5-~1\\BDV\\*.*" ascii //weight: 1
        $x_1_4 = "BDV\\aUtoRuN.inF" ascii //weight: 1
        $x_1_5 = "xcopy BDV.exe C:\\RECYCLER\\S-1-5-~1\\BDV\\ /h /k /y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_Win32_Autorun_AFA_2147656127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AFA"
        threat_id = "2147656127"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 57 00 6f 00 72 00 6d 00 2b 00 54 00 72 00 6f 00 6a 00 61 00 6e 00 [0-18] 5c 00 77 00 6f 00 72 00 6d 00 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = "autorun.inf" wide //weight: 1
        $x_1_3 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 5c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_1_5 = "<bks>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AFC_2147656258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AFC"
        threat_id = "2147656258"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "/pnl/gate.php" ascii //weight: 2
        $x_2_2 = {5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 [0-10] 5b 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00}  //weight: 2, accuracy: Low
        $x_1_3 = "DDOS STARTED" wide //weight: 1
        $x_1_4 = "BRUTE STARTED" wide //weight: 1
        $x_1_5 = "#winlock" wide //weight: 1
        $x_1_6 = "FileZilla\\recentservers.xml" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_AFV_2147658204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AFV"
        threat_id = "2147658204"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{hifaggot}" ascii //weight: 1
        $x_1_2 = "Flooding done." ascii //weight: 1
        $x_1_3 = "Start flooding." ascii //weight: 1
        $x_1_4 = "Fail Err0r.." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AGC_2147659301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AGC"
        threat_id = "2147659301"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\WINDOWS\\Temp\\smss0.exe" wide //weight: 1
        $x_1_2 = "open=RECICLER\\S-1-" wide //weight: 1
        $x_1_3 = "\\autorun.inf" wide //weight: 1
        $x_1_4 = "shutdown.exe -s -t" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Autorun_AGD_2147659400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AGD"
        threat_id = "2147659400"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 52 45 43 59 43 4c 45 52 00 00 00 2e 3a 3a 5b 55 73 62 5d 3a 3a 2e 20 49 6e 66 65 63 74 65 64 20 64 72 69 76 65 3a 20 25 73}  //weight: 2, accuracy: High
        $x_1_2 = "\\autorun.inf" ascii //weight: 1
        $x_1_3 = "HOST: www.adobe.com.cn" ascii //weight: 1
        $x_1_4 = "del %%0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_AGE_2147659919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AGE"
        threat_id = "2147659919"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SecureDeskv2.Document\\shell\\open\\command" wide //weight: 1
        $x_1_2 = "\\New Folder .exe" wide //weight: 1
        $x_1_3 = {61 00 20 00 2d 00 72 00 30 00 20 00 2d 00 74 00 61 00 32 00 30 00 31 00 30 00 30 00 31 00 30 00 31 00 20 00 2d 00 73 00 6c 00 31 00 30 00 32 00 34 00 30 00 30 00 30 00 20 00 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 65 00 62 00 75 00 67 00 5c 00 6e 00 65 00 77 00 5c 00 72 00 66 00 31 00 30 00 2e 00 72 00 61 00 20 00 ?? ?? 3a 00 5c 00 2a 00 2e 00 64 00 6f 00 63 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\com1.{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\driveinfo.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AGG_2147660297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AGG"
        threat_id = "2147660297"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "57"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mmc32.exe" ascii //weight: 10
        $x_10_2 = "autorun.inf" ascii //weight: 10
        $x_10_3 = "%s Infect file %s OK!" ascii //weight: 10
        $x_10_4 = "%s Create file %s OK!" ascii //weight: 10
        $x_10_5 = "S-1-5-21-1078073611-1993962763-839522115-1003" ascii //weight: 10
        $x_1_6 = "NetManage" ascii //weight: 1
        $x_1_7 = "DontSee" ascii //weight: 1
        $x_1_8 = "sr1000R.dll" ascii //weight: 1
        $x_1_9 = "c:\\as11" ascii //weight: 1
        $x_1_10 = "recent.cab" ascii //weight: 1
        $x_1_11 = "\\desktop.ini" ascii //weight: 1
        $x_1_12 = "IP Address List:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AGI_2147663212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AGI"
        threat_id = "2147663212"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "124"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "%c:\\autorun.inf" ascii //weight: 100
        $x_1_2 = "%c:\\downloads.exe" ascii //weight: 1
        $x_1_3 = "%c:\\documents.exe" ascii //weight: 1
        $x_1_4 = "%c:\\pics.exe" ascii //weight: 1
        $x_1_5 = "%c:\\fun.exe" ascii //weight: 1
        $x_1_6 = "open=downloads.exe" ascii //weight: 1
        $x_1_7 = "open=documents.exe" ascii //weight: 1
        $x_1_8 = "open=pics.exe" ascii //weight: 1
        $x_1_9 = "open=fun.exe" ascii //weight: 1
        $x_10_10 = "e:\\new folder.exe" ascii //weight: 10
        $x_10_11 = "f:\\new folder.exe" ascii //weight: 10
        $x_10_12 = "g:\\new folder.exe" ascii //weight: 10
        $x_10_13 = "\\crazya.exe" ascii //weight: 10
        $x_10_14 = "gods must be creazy!" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_AGJ_2147663533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AGJ"
        threat_id = "2147663533"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5b 00 41 00 75 00 74 00 6f 00 52 00 75 00 6e 00 5d 00 0a 00 00 00 00 00 6f 00 70 00 65 00 6e 00 3d 00 0a 00 00 00 00 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d [0-128] 5c 00 6d 00 73 00 6d 00 73 00 67 00 73 00 2e 00 70 00 69 00 66}  //weight: 10, accuracy: Low
        $x_10_2 = "New Document .exe" wide //weight: 10
        $x_1_3 = "\\Outdir.bat" wide //weight: 1
        $x_1_4 = "fpco.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_AGK_2147663536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AGK"
        threat_id = "2147663536"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 7d f0 05 7f ?? 8b 45 f0 8b 44 85 c8 89 44 24 04 8b 45 f4 8b 44 85 c8 89 04 24 e8 ?? ?? ?? ?? 8d 45 f0 ff 00 eb}  //weight: 2, accuracy: Low
        $x_1_2 = "open=\"SVCHOST.com /s" ascii //weight: 1
        $x_1_3 = "autorun.inf" ascii //weight: 1
        $x_1_4 = "DESTORY_ZZ_%d" ascii //weight: 1
        $x_1_5 = "wjview32.com /s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_AGR_2147671589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AGR"
        threat_id = "2147671589"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "FUCK ANTIVIERS" ascii //weight: 10
        $x_10_2 = "All diretroy files will been copied!" ascii //weight: 10
        $x_1_3 = "secur16.dll" ascii //weight: 1
        $x_1_4 = "\\usbprotect.exe" ascii //weight: 1
        $x_1_5 = "\\~bandu.tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_AGR_2147671589_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AGR"
        threat_id = "2147671589"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 75 63 6b [0-32] 55 53 42 20 68 61 73 20 62 65 65 6e 20 67 61 6e 72 61 6e 67 21}  //weight: 10, accuracy: Low
        $x_10_2 = "Remote computer will been sleepped for %d" ascii //weight: 10
        $x_1_3 = "InitBackDoor() OK " ascii //weight: 1
        $x_1_4 = "Dll has been deleted,recover it from memory!" ascii //weight: 1
        $x_1_5 = "bond008.jpg" ascii //weight: 1
        $x_1_6 = "\\usbprotect.exe" ascii //weight: 1
        $x_1_7 = "\\mssign16.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Autorun_AGT_2147677645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AGT"
        threat_id = "2147677645"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\WINDOWS\\system32\\Karnel368.exe" wide //weight: 1
        $x_1_2 = {3a 00 5c 00 41 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 00 00 1a 00 00 00 3a 00 5c 00 41 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AGT_2147677645_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AGT"
        threat_id = "2147677645"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 73 65 63 72 65 74 2e 65 78 65 [0-16] 5c 61 75 74 6f 72 75 6e 2e 69 6e 66}  //weight: 1, accuracy: Low
        $x_1_2 = "You system infected by Slash Worm!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AGY_2147678528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AGY"
        threat_id = "2147678528"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {6e 65 77 55 73 62 00 00 4d 61 63 68 69 6e 65 4e 61 6d 65}  //weight: 3, accuracy: High
        $x_3_2 = "open=C:\\C0MM\\C0MM" wide //weight: 3
        $x_2_3 = "cmd.exe /c net share SYS_" wide //weight: 2
        $x_1_4 = "ShowSuperHidden /t REG_DWORD /d 0 /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AGZ_2147678534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AGZ"
        threat_id = "2147678534"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 73 65 63 72 65 74 2e 65 78 65 [0-16] 5c 61 75 74 6f 72 75 6e 2e 69 6e 66}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 5c 31 39 32 2e 31 36 38 2e 30 2e [0-3] 5c 73 65 63 72 65 74 2e 65 78 65 [0-3] 5c 5c 31 39 32 2e 31 36 38 2e 30 2e [0-3] 5c 73 65 63 72 65 74 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AHA_2147679363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AHA"
        threat_id = "2147679363"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RECYCLED\\NTDETECT.EXE" ascii //weight: 1
        $x_1_2 = "api.hostip.info/country.php?ip=" ascii //weight: 1
        $x_1_3 = "upfile nok" ascii //weight: 1
        $x_1_4 = "Start logging..." ascii //weight: 1
        $x_1_5 = {41 75 74 6f 72 75 6e 2e 69 6e 66 00 5b 61 75 74 6f 72 75 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_LF_2147720822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.LF!bit"
        threat_id = "2147720822"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 74 74 72 69 62 20 2b 48 20 2b 53 20 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 5c [0-32] 20 3e 6e 75 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {72 65 67 20 61 64 64 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 56 [0-32] 2f 54 20 52 45 47 5f 53 5a 20 2f 44}  //weight: 1, accuracy: Low
        $x_1_3 = {72 65 67 20 61 64 64 20 22 48 4b 43 55 5c 43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 44 65 73 6b 74 6f 70 22 20 2f 56 [0-32] 2f 54 20 52 45 47 5f 53 5a 20 2f 44 20 22 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c [0-32] 2e 73 63 72}  //weight: 1, accuracy: Low
        $x_1_4 = {70 69 6e 67 20 2d 6c 20 31 30 32 34 30 [0-64] 20 3e 6e 75 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_XXZ_2147733089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.XXZ!bit"
        threat_id = "2147733089"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "svchost32.exe" wide //weight: 1
        $x_1_2 = "Autorun.inf" wide //weight: 1
        $x_1_3 = "PROCESSCLOSE ( \"avast.exe\" )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AJA_2147735185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AJA!bit"
        threat_id = "2147735185"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "autorun.inf" wide //weight: 1
        $x_1_2 = "/c rmdir /q /s" wide //weight: 1
        $x_1_3 = ":Zone.Identifier" wide //weight: 1
        $x_1_4 = "\\_\\DeviceManager.exe" wide //weight: 1
        $x_1_5 = "DisableScanOnRealtimeEnable" wide //weight: 1
        $x_1_6 = "DisableBehaviorMonitoring" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_DU_2147742805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.DU!MTB"
        threat_id = "2147742805"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Gaara.exe" wide //weight: 1
        $x_1_2 = "Wscript.Shell" wide //weight: 1
        $x_1_3 = "GetDriveTypeA" ascii //weight: 1
        $x_1_4 = "KillAV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_KA_2147745741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.KA!MTB"
        threat_id = "2147745741"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "autorun.inf" ascii //weight: 1
        $x_1_2 = ":\\windows\\svchost.exe" ascii //weight: 1
        $x_1_3 = "shellAutoruncommand=" ascii //weight: 1
        $x_1_4 = "CurrentVersion\\Policies\\Explorer\\DisallowRun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Autorun_AQ_2147830406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Autorun.AQ!MTB"
        threat_id = "2147830406"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 41 00 ab 33 41 00 d4 33 41 00 e0 33 41 00 09 34 41 00 1a 35 41 00 3f 35 41}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

