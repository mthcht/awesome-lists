rule TrojanSpy_Win32_VB_KB_2147575261_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VB.KB"
        threat_id = "2147575261"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "n-keylogger@gmail.com" wide //weight: 5
        $x_5_2 = "type32" ascii //weight: 5
        $x_1_3 = "{ScrollLock}" wide //weight: 1
        $x_1_4 = "{PrintScreen}" wide //weight: 1
        $x_1_5 = "{BackSpace}" wide //weight: 1
        $x_1_6 = "{F-1}" wide //weight: 1
        $x_1_7 = "{F-12}" wide //weight: 1
        $x_5_8 = "SUBJECT: Tarih:" wide //weight: 5
        $x_5_9 = "\\system32\\type32.exe:*:Enabled:type32" wide //weight: 5
        $x_1_10 = "ckie v ms" wide //weight: 1
        $x_1_11 = "Bilgisayar ad" wide //weight: 1
        $x_1_12 = " ve cookieler " wide //weight: 1
        $x_5_13 = "\\system32\\drivers\\optrves.sys" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 5 of ($x_1_*))) or
            ((5 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_VB_KC_2147575269_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VB.KC"
        threat_id = "2147575269"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "!!!!'''TpTAyarlarB" wide //weight: 5
        $x_1_2 = "spysilici.bat" wide //weight: 1
        $x_5_3 = "TpT Spy Keylogger V1.0 (Loaded At " wide //weight: 5
        $x_1_4 = " ***************** Sistem Bilgisi *****************" wide //weight: 1
        $x_1_5 = "lemler Listesi *****************" wide //weight: 1
        $x_1_6 = " ***************** Pano De" wide //weight: 1
        $x_1_7 = "imleri *****************" wide //weight: 1
        $x_1_8 = " ***************** Klavye Girdileri *****************" wide //weight: 1
        $x_1_9 = "Sistem bilgisi : " wide //weight: 1
        $x_1_10 = "lemci: " wide //weight: 1
        $x_1_11 = "Toplam Bellek: " wide //weight: 1
        $x_1_12 = "WINDOWS Versiyonu: " wide //weight: 1
        $x_1_13 = "Bilgisayar Ad" wide //weight: 1
        $x_1_14 = "@TpTLabs.com" wide //weight: 1
        $x_1_15 = " [ Capslock=A" wide //weight: 1
        $x_1_16 = " [ Capslock=Kapal" wide //weight: 1
        $x_1_17 = " [ Numlock=A" wide //weight: 1
        $x_1_18 = " [ Numlock=Kapal" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((15 of ($x_1_*))) or
            ((1 of ($x_5_*) and 10 of ($x_1_*))) or
            ((2 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_VB_JE_2147583316_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VB.JE"
        threat_id = "2147583316"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2000"
        strings_accuracy = "Low"
    strings:
        $x_1000_1 = {56 50 ff d7 8b 45 e0 50 68 ?? ?? 40 00 eb 5a 85 c0 75 0c 68 ?? ?? 40 00 68 ?? ?? 40 00 ff d3 8b 35 ?? ?? 40 00 8b 0e 8d 55 d8 52 56 ff 51 14 db e2 85 c0 7d 0b 6a 14 68 ?? ?? 40 00 56 50 ff d7 8b 45 d8 8b f0 8b 08 8d 55 e0 52 50 ff 51 50 db e2 85 c0 7d 0b 6a 50 68 ?? ?? 40 00 56 50 ff d7 8b 45 e0 50 68 ?? ?? 40 00}  //weight: 1000, accuracy: Low
        $x_1000_2 = {ff 15 30 10 40 00 8b d0 8d 4d dc ff 15 fc 10 40 00 50 6a 01 6a ff 6a 01 ff 15 bc 10 40 00 8d 4d dc 51 8d 55 e0 52 6a 02 ff 15 d0 10 40 00 83 c4 0c 8d 4d d8 ff 15 10 11 40 00 8b 45 08 8d 70 34 6a 01 56 ff 15 14 10 40 00 ff 15 4c 10 40 00 8b 0e 51 6a 00 ff 15 74 10 40 00 85 c0 75 1a ba ?? ?? 40 00 8b ce eb 0b ba ?? ?? 40 00 8b 45 08 8d 48 34}  //weight: 1000, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_VB_LA_2147595821_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VB.LA"
        threat_id = "2147595821"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "83"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Explorer\\Advanced\\ShowSuperHidden" wide //weight: 10
        $x_10_2 = "Explorer\\Advanced\\HideFileExt" wide //weight: 10
        $x_10_3 = "InternetGetConnectedState" ascii //weight: 10
        $x_10_4 = "URLDownloadToCacheFileA" ascii //weight: 10
        $x_10_5 = {6d 6f 64 4b 65 79 73 00}  //weight: 10, accuracy: High
        $x_10_6 = "GetAsyncKeyState" ascii //weight: 10
        $x_10_7 = "keybd_event" ascii //weight: 10
        $x_10_8 = "Start Log: " wide //weight: 10
        $x_1_9 = "Copia de explorer" ascii //weight: 1
        $x_1_10 = "Keylggr" wide //weight: 1
        $x_1_11 = "{GTDC6DJ0-OTRW-U5GH-S1EE-E0AC10B4E666}" wide //weight: 1
        $x_1_12 = "{F146C9B1-VMVQ-A9RC-FLUK-D0BA86B4E999}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_VB_BA_2147596911_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VB.BA"
        threat_id = "2147596911"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "DllFunctionCall" ascii //weight: 10
        $x_10_3 = ".qmail@" wide //weight: 10
        $x_10_4 = "F:\\prog lang\\visual basic\\edu\\hack\\key logger\\EgySpy v1.11\\server\\EgySpy.vbp" wide //weight: 10
        $x_1_5 = "EgySpy" ascii //weight: 1
        $x_1_6 = "KEYLOG" ascii //weight: 1
        $x_1_7 = "AppEgySpy" ascii //weight: 1
        $x_1_8 = "HELO" wide //weight: 1
        $x_1_9 = "MAIL FROM: <" wide //weight: 1
        $x_1_10 = "RCPT TO: <" wide //weight: 1
        $x_1_11 = "Reply-to:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_VB_DA_2147598064_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VB.DA"
        threat_id = "2147598064"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "txtHataGoster" ascii //weight: 1
        $x_1_2 = "txtHataBaslik" ascii //weight: 1
        $x_1_3 = "mswinsck.ocx" ascii //weight: 1
        $x_1_4 = "wscript.shell" wide //weight: 1
        $x_1_5 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost" wide //weight: 1
        $x_1_6 = "Content-Type: text/" wide //weight: 1
        $x_1_7 = "KEYLOGGER RECORDS:" wide //weight: 1
        $x_1_8 = "[BackSpace]" wide //weight: 1
        $x_1_9 = "[Delete]" wide //weight: 1
        $x_1_10 = "IP Address(es):" wide //weight: 1
        $x_1_11 = "Sending Mail" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule TrojanSpy_Win32_VB_EU_2147598485_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VB.EU"
        threat_id = "2147598485"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sysver.exe;sysinfo.exe;syslnfo.exe;syschost.exe;netcmd.exe;netconfig.exe;systemchk.exe;csrcs.exe" wide //weight: 10
        $x_1_2 = "Microsoft\\Network\\Connections\\pbk\\rasphone.pbk" wide //weight: 1
        $x_1_3 = "Software\\Yahoo\\Pager" wide //weight: 1
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" wide //weight: 1
        $x_1_5 = "SYSTEM\\CurrentControlSet\\Services\\TlntSvr" wide //weight: 1
        $x_1_6 = "SOFTWARE\\KasperskyLab" wide //weight: 1
        $x_1_7 = "Software\\Zone Labs\\ZoneAlarm" wide //weight: 1
        $x_1_8 = "<script language=vbscript>form9.submit</script>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_VB_AM_2147599259_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VB.AM"
        threat_id = "2147599259"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Get Pass From :" wide //weight: 1
        $x_1_2 = "kar kard" wide //weight: 1
        $x_1_3 = "This Is Game Port Password" wide //weight: 1
        $x_1_4 = "&Remember my ID && password" wide //weight: 1
        $x_1_5 = "Y! Password :" wide //weight: 1
        $x_1_6 = "net stop" wide //weight: 1
        $x_1_7 = "YahooBuddyMain" wide //weight: 1
        $x_10_8 = "MSVBVM60.DLL" ascii //weight: 10
        $x_1_9 = "\\drivers\\disdn\\d.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_VB_GT_2147599858_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VB.gen!GT"
        threat_id = "2147599858"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" wide //weight: 1
        $x_1_2 = "[Log Start:" wide //weight: 1
        $x_1_3 = "[Log End:" wide //weight: 1
        $x_1_4 = "Beginning transfer of body..." wide //weight: 1
        $x_1_5 = "content of logfile to be mailed" ascii //weight: 1
        $x_1_6 = "smtpmailer" ascii //weight: 1
        $x_1_7 = "\\VB98\\VB6.OLB" ascii //weight: 1
        $x_1_8 = ".qmail@" wide //weight: 1
        $x_1_9 = {57 00 69 00 6c 00 6c 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 69 00 6e 00 20 00 36 00 30 00 20 00 73 00 65 00 63 00 6f 00 6e 00 64 00 73 00 00 00 00 00 36 00 00 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 20 00 73 00 6f 00 63 00 6b 00 65 00 74 00 20 00 72 00 65 00 74 00 75 00 72 00 6e 00 20 00 76 00 61 00 6c 00 75 00 65 00 00 00 1a 00 00 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 65 00 64 00 20 00 74 00 6f 00 20 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_VB_AC_2147602546_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VB.AC"
        threat_id = "2147602546"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "WindowsUpdata" ascii //weight: 10
        $x_10_2 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_3 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_4 = "whereAmI" ascii //weight: 10
        $x_1_5 = {69 00 66 00 20 00 65 00 78 00 69 00 73 00 74 00 20 00 00 00 1c 00 00 00 20 00 67 00 6f 00 74 00 6f 00 20 00 73 00 65 00 6c 00 66 00 6b 00 69 00 6c 00 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = "&username=" wide //weight: 1
        $x_1_7 = "ONLINE - (" wide //weight: 1
        $x_1_8 = "C:\\tmpsss.log" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_VB_AAI_2147604823_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VB.AAI"
        threat_id = "2147604823"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "prutect.com" wide //weight: 10
        $x_10_2 = "SOFTWARE\\E2G" wide //weight: 10
        $x_10_3 = "{7abadff8-0be3-4560-9c7a-62aa88150a20}" wide //weight: 10
        $x_10_4 = "prjPrutect" wide //weight: 10
        $x_3_5 = "\\Spybot - Search & Destroy\\spybotsd.exe" wide //weight: 3
        $x_3_6 = "AdAware6" wide //weight: 3
        $x_3_7 = "Norton Internet Security" wide //weight: 3
        $x_1_8 = "\\keylog.~" wide //weight: 1
        $x_1_9 = "{ENTER}" wide //weight: 1
        $x_1_10 = "{DOWN}" wide //weight: 1
        $x_1_11 = "PRINTSCREEN" wide //weight: 1
        $x_1_12 = "SCROLLLOCK" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_VB_FA_2147608805_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VB.FA"
        threat_id = "2147608805"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\Policies\\explorer\\run\\" wide //weight: 1
        $x_1_2 = {53 00 72 00 76 00 44 00 74 00 6c 00 00 00 00 00 10 00 00 00 55 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 00 00 00 00 18 00 00 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 6e 00 61 00 6d 00 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\norton AV\\navw32.exe" wide //weight: 1
        $x_1_4 = "\\McAfee\\McAfee VirusScan\\alogserv.exe" wide //weight: 1
        $x_1_5 = {20 00 2d 00 20 00 41 00 62 00 73 00 65 00 6e 00 74 00 20 00 44 00 72 00 69 00 76 00 65 00 00 00 22 00 00 00 20 00 2d 00 20 00 52 00 65 00 6d 00 6f 00 76 00 61 00 62 00 6c 00 65 00 20 00 44 00 69 00 73 00 6b 00}  //weight: 1, accuracy: High
        $x_1_6 = "DisableFirewall" ascii //weight: 1
        $x_1_7 = "ShellExecuteA" ascii //weight: 1
        $x_1_8 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_Win32_VB_BZ_2147627098_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VB.BZ"
        threat_id = "2147627098"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 6f 64 48 6f 6f 6b 00 6d 6f 64 4d 61 69 6e 00 6d 6f 64 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_2 = "-sysrun" wide //weight: 1
        $x_1_3 = {7f 0c 00 f3 ff 7f c4 e7 f5 00 00 01 00 b2 7f 0c 00 f3 00 80 c4 f4 00 cb e7 f5 00 00 00 80 c4 c5 7f 10 00 f3 ff 7f c4 e7 7f 10 00 f3 00 80 c4 f4 00 cb e7 f5 00 80 00 00 c4 c5 c5}  //weight: 1, accuracy: High
        $x_1_4 = {3a 00 38 00 38 00 2f 00 70 00 36 00 2e 00 61 00 73 00 70 00 3f 00 4d 00 41 00 43 00 3d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_VB_CS_2147638322_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VB.CS"
        threat_id = "2147638322"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Command.asp?msg=" wide //weight: 1
        $x_3_2 = "\\Pusmint\\svchost.exe" wide //weight: 3
        $x_1_3 = "net stop sharedaccess" wide //weight: 1
        $x_1_4 = "ftp -i -s:" wide //weight: 1
        $x_3_5 = "\\Pusmint\\SystemDir.bat" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_VB_DE_2147639533_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VB.DE"
        threat_id = "2147639533"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[PageDown]" wide //weight: 1
        $x_1_2 = "mkdir /public_html/Keylogg/" wide //weight: 1
        $x_1_3 = "PicFormat32a.PicFormat32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_VB_DM_2147641920_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VB.DM"
        threat_id = "2147641920"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "pc-scripts.no-ip.org" wide //weight: 3
        $x_2_2 = "C:\\WINDOWS\\WINDOWSFILES.exe" wide //weight: 2
        $x_2_3 = "HKCU\\Software\\yahoo\\pager\\ETS" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_VB_ED_2147643546_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VB.ED"
        threat_id = "2147643546"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\NotPHP +RSRC SQlite\\sm.vbp" wide //weight: 2
        $x_1_2 = "iGrabber" wide //weight: 1
        $x_1_3 = "-Dev-Point.CoM" wide //weight: 1
        $x_1_4 = "Password:" wide //weight: 1
        $x_1_5 = "No-IP not installed." wide //weight: 1
        $x_1_6 = "Yahoo! ETC" wide //weight: 1
        $x_1_7 = "Firefox" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_VB_EJ_2147653815_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VB.EJ"
        threat_id = "2147653815"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\SmartCard" wide //weight: 1
        $x_1_2 = "SOFTWARE\\YahooMessenger" wide //weight: 1
        $x_1_3 = {43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 [0-48] 4e 00 6f 00 46 00 6f 00 6c 00 64 00 65 00 72 00 4f 00 70 00 74 00 69 00 6f 00 6e 00 73 00}  //weight: 1, accuracy: Low
        $x_1_4 = {77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 72 00 75 00 6e 00 ?? ?? ?? ?? ?? ?? 63 00 73 00 72 00 73 00 73 00 ?? ?? ?? ?? ?? ?? 63 00 73 00 72 00 73 00 73 00 31 00}  //weight: 1, accuracy: Low
        $x_1_5 = "rpool\\smss.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_VB_EK_2147655080_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VB.EK"
        threat_id = "2147655080"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 00 00 0e 00 00 00 64 00 6f 00 6d 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "http://64.15.147.205/~finance/" wide //weight: 1
        $x_1_3 = "\\Mail1.htm" wide //weight: 1
        $x_1_4 = "HIDE!!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_VB_EL_2147661430_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VB.EL"
        threat_id = "2147661430"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HAKOPS LOGGER" wide //weight: 1
        $x_1_2 = "malar\\" wide //weight: 1
        $x_1_3 = "\\Shot\\Resim.jpg" wide //weight: 1
        $x_1_4 = "msnstealer" ascii //weight: 1
        $x_1_5 = "[Pause|Break]" wide //weight: 1
        $x_1_6 = "\\GoogleUpdate.exe" wide //weight: 1
        $x_1_7 = "-[KOPYALANDI]-" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

