rule Trojan_Win32_VB_AT_2147500903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.AT"
        threat_id = "2147500903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AT 9:00 /interactive /every:M,T,W,Th,F,S,Su " wide //weight: 1
        $x_1_2 = "AT 14:00 /interactive /every:M,T,W,Th,F,S,Su " wide //weight: 1
        $x_1_3 = "Fuck U,Please Don't Take My Clothes Off!!!" wide //weight: 1
        $x_1_4 = "GetKeyState" ascii //weight: 1
        $x_1_5 = "net start schedule" wide //weight: 1
        $x_1_6 = "ShellExecuteA" ascii //weight: 1
        $x_1_7 = "config\\Info.ini" wide //weight: 1
        $x_1_8 = "dnfdnf.asp?msg=" wide //weight: 1
        $x_1_9 = "svchost.exe" wide //weight: 1
        $x_1_10 = "\"% uHC" ascii //weight: 1
        $x_1_11 = "20090221" wide //weight: 1
        $x_1_12 = "rundll32.com" wide //weight: 1
        $x_1_13 = "UserSetting.ini" wide //weight: 1
        $x_1_14 = "NO!NO!NO!" wide //weight: 1
        $x_1_15 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_16 = "Macrom\\ScheTime.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_BD_2147502864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.BD"
        threat_id = "2147502864"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\AC:\\Documents and Settings\\Florin\\Desktop\\Evoloution\\Server\\Server.vbp" wide //weight: 10
        $x_10_2 = {7b 00 45 00 6e 00 74 00 65 00 72 00 7d 00 00 00 08 00 00 00 7b 00 42 00 53 00 7d 00}  //weight: 10, accuracy: High
        $x_1_3 = "ghjita" ascii //weight: 1
        $x_1_4 = "muhaha" ascii //weight: 1
        $x_10_5 = "MSWinsockLib" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_CT_2147504503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.CT"
        threat_id = "2147504503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Autorun.inf" wide //weight: 10
        $x_10_2 = "odbcad32.exe" wide //weight: 10
        $x_10_3 = "NoDriveTypeAutoRun" wide //weight: 10
        $x_10_4 = "attachment*.tmp" wide //weight: 10
        $x_1_5 = "shellexecute=.\\recycled\\" ascii //weight: 1
        $x_1_6 = {73 68 65 6c 6c 5c [0-4] 5c 43 6f 6d 6d 61 6e 64 3d 2e 5c 72 65 63 79 63 6c 65 64 5c}  //weight: 1, accuracy: Low
        $x_1_7 = "open=.\\recycled\\" ascii //weight: 1
        $x_1_8 = {52 00 65 00 63 00 79 00 63 00 6c 00 65 00 64 00 5c 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_ZE_2147584800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ZE"
        threat_id = "2147584800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\Mom\\Knamemom.vbp" wide //weight: 10
        $x_10_2 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 [0-16] 70 00 6f 00 70 00}  //weight: 10, accuracy: Low
        $x_5_3 = "/Config/programupdate.asp" wide //weight: 5
        $x_5_4 = "Knamemom.exe" wide //weight: 5
        $x_5_5 = "Knameproc.exe" wide //weight: 5
        $x_3_6 = "78E1BDD1-9941-11cf-9756-00AA00C00908" wide //weight: 3
        $x_2_7 = "software\\microsoft\\windows\\currentversion\\run" wide //weight: 2
        $x_1_8 = "http://www.goldentech.co.kr" wide //weight: 1
        $x_1_9 = "http://www.hebogo.com/ac" wide //weight: 1
        $x_1_10 = "http://www.microname.co.kr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_ZF_2147592461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ZF"
        threat_id = "2147592461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "###,###,###,##0 f\\i\\l\\e\\s\\ \\f\\o\\u\\n\\d" wide //weight: 10
        $x_10_2 = "http://www1.yzsc.cn/cash" wide //weight: 10
        $x_10_3 = "VB5!6&vb6chs.dll" ascii //weight: 10
        $x_1_4 = "Shell DocObject View" wide //weight: 1
        $x_1_5 = "execScript" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_ZG_2147592462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ZG"
        threat_id = "2147592462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\WEBPNT\\weBpnt.VBp" wide //weight: 10
        $x_10_2 = "modHideProcess" ascii //weight: 10
        $x_10_3 = "Microsoft Web Printer" wide //weight: 10
        $x_2_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_2_5 = "SYSTEM\\CurrentControlSet\\Services\\" wide //weight: 2
        $x_2_6 = "\\Program Files\\Internet Explorer\\IEXPLORE.EXE" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_AAB_2147592557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.AAB"
        threat_id = "2147592557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "61"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "By Eddy-K" wide //weight: 10
        $x_10_2 = "http, https & Outlook Express" wide //weight: 10
        $x_10_3 = "/smtpserver smtp.web.de /to" wide //weight: 10
        $x_10_4 = "/from Universal1337" wide //weight: 10
        $x_10_5 = "kill.bat" wide //weight: 10
        $x_10_6 = "taskkill /f /im" wide //weight: 10
        $x_1_7 = "C:\\inet.txt" wide //weight: 1
        $x_1_8 = "C:\\msg.txt" wide //weight: 1
        $x_1_9 = "C:\\pdk.txt" wide //weight: 1
        $x_1_10 = "C:\\http.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_ZH_2147594862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ZH"
        threat_id = "2147594862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "62"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "MSVBVM60.DLL" ascii //weight: 5
        $x_5_2 = "CreateToolhelp32Snapshot" ascii //weight: 5
        $x_5_3 = "Process32First" ascii //weight: 5
        $x_5_4 = "Process32Next" ascii //weight: 5
        $x_5_5 = "FindWindowExA" ascii //weight: 5
        $x_5_6 = "ShellExecuteA" ascii //weight: 5
        $x_5_7 = "smhost.exe" wide //weight: 5
        $x_5_8 = "servlogon.exe" wide //weight: 5
        $x_5_9 = "\\IPC$" wide //weight: 5
        $x_5_10 = "\\ADMIN$" wide //weight: 5
        $x_5_11 = "ShowPopups" wide //weight: 5
        $x_3_12 = "xxxx.com" wide //weight: 3
        $x_3_13 = "17tahun.com" wide //weight: 3
        $x_1_14 = {5c 00 43 00 79 00 72 00 61 00 78 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_AAC_2147595101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.AAC"
        threat_id = "2147595101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "rundll32.exe mouse,disable" wide //weight: 10
        $x_10_2 = "rundll32.exe keyboard,disable" wide //weight: 10
        $x_5_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 5
        $x_5_4 = "BlockInput" ascii //weight: 5
        $x_2_5 = "C:\\pinoy.exe" wide //weight: 2
        $x_2_6 = "C:\\windows\\pinoy.exe" wide //weight: 2
        $x_2_7 = "C:\\windows\\system\\pinoy.exe" wide //weight: 2
        $x_2_8 = "C:\\windows\\system32\\pinoy.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_AAD_2147595137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.AAD"
        threat_id = "2147595137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Buat Virus\\Virus VBBEGO\\Kolaborasi baru PerangVir\\Project1.vbp" wide //weight: 10
        $x_5_2 = "Game Perang Dunia II.exe" wide //weight: 5
        $x_5_3 = "Kalo Anda Sadar, Komputer Anda akan tetap Aman dari Virus Moral." wide //weight: 5
        $x_1_4 = "TerminateProcess" ascii //weight: 1
        $x_1_5 = "OpenProcess" ascii //weight: 1
        $x_1_6 = "Process32First" ascii //weight: 1
        $x_1_7 = "Process32Next" ascii //weight: 1
        $x_1_8 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_AAE_2147595753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.AAE"
        threat_id = "2147595753"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\Virus Project\\CopyA\\CopyA.vbp" wide //weight: 5
        $x_5_2 = "\\Start Menu\\Programs\\Startup" wide //weight: 5
        $x_5_3 = "Generate by ARE-2004, Author by Puji Susanto$" ascii //weight: 5
        $x_1_4 = "ShellExecuteA" ascii //weight: 1
        $x_1_5 = "ExitWindowsEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_AAH_2147596344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.AAH"
        threat_id = "2147596344"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sharK\\Server\\Projekt1.vbp" wide //weight: 10
        $x_10_2 = "Windows Update" ascii //weight: 10
        $x_5_3 = "\\system32\\drivers\\etc\\hosts" wide //weight: 5
        $x_5_4 = "mswinsck.oca" ascii //weight: 5
        $x_1_5 = "\\shark.update" wide //weight: 1
        $x_1_6 = "iamasharkplugin" wide //weight: 1
        $x_1_7 = "\\regssvr32.bat" wide //weight: 1
        $x_1_8 = "start " wide //weight: 1
        $x_1_9 = "Received_File" wide //weight: 1
        $x_1_10 = "{BROWSER}" wide //weight: 1
        $x_1_11 = "{ENTER}" wide //weight: 1
        $x_1_12 = "{BACK}" wide //weight: 1
        $x_1_13 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_14 = "DeleteFolder" wide //weight: 1
        $x_1_15 = "regsvr32 /s /u \"" wide //weight: 1
        $x_1_16 = "privmsg" wide //weight: 1
        $x_1_17 = "killproc" wide //weight: 1
        $x_1_18 = "Chat has been started" wide //weight: 1
        $x_1_19 = "URLDownloadToFileA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_KT_2147596405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.KT"
        threat_id = "2147596405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "AtiKu Loro" ascii //weight: 10
        $x_10_2 = "Soccer Mania.exe" ascii //weight: 10
        $x_10_3 = "OpenProcess" ascii //weight: 10
        $x_10_4 = "AdjustTokenPrivileges" ascii //weight: 10
        $x_10_5 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_1_6 = "\\Buat Virus\\Virus VBBEGO\\Kolaborasi baru SoccerVir\\Project1.vbp" wide //weight: 1
        $x_1_7 = "Udah yach bye - bye! Cup - cup waw - waw (^_^) -goaal -- goooal -- gooal !!!" wide //weight: 1
        $x_1_8 = "(I LOVE YOU ALL) </h4></CENTER></BODY></HTML>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_DNA_2147597131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.DNA"
        threat_id = "2147597131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "VIRUS" ascii //weight: 10
        $x_10_2 = "Trojan" ascii //weight: 10
        $x_10_3 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_4 = "28C4C820-401A-101B-A3C9-08002B2F49FB" wide //weight: 10
        $x_10_5 = "D:\\virustrojan\\harpotinfeksiexe\\harpotinfeksiexe\\SERVER.VBP" wide //weight: 10
        $x_1_6 = "RUNDLL32.EXE" wide //weight: 1
        $x_1_7 = "waveOutGetNumDevs" ascii //weight: 1
        $x_1_8 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_9 = "shell32.dll,OpenAs_RunDLL" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_DNB_2147597132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.DNB"
        threat_id = "2147597132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "75"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "fzx9823.vbp" wide //weight: 10
        $x_10_3 = "{GTDC6DJ0-OTRW-U5GH-S1EE-E0AC10B4E666}" wide //weight: 10
        $x_10_4 = "{F146C9B1-VMVQ-A9RC-FLUK-D0BA86B4E999}" wide //weight: 10
        $x_10_5 = "explorer.exe" wide //weight: 10
        $x_10_6 = "svchost.exe" wide //weight: 10
        $x_10_7 = "fzx9823.exe" wide //weight: 10
        $x_1_8 = "modKeys" ascii //weight: 1
        $x_1_9 = "UserInit" ascii //weight: 1
        $x_1_10 = "ReadMemory" ascii //weight: 1
        $x_1_11 = "VerificarArchivo" ascii //weight: 1
        $x_1_12 = "Copia de explorer" ascii //weight: 1
        $x_1_13 = "ShellExecuteA" ascii //weight: 1
        $x_1_14 = "URLDownloadToCacheFileA" ascii //weight: 1
        $x_1_15 = "InternetGetConnectedState" ascii //weight: 1
        $x_1_16 = "http://e223pg.awardspace.co.uk/up.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_DNC_2147597133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.DNC"
        threat_id = "2147597133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "wxr\"\"/p" ascii //weight: 10
        $x_10_2 = "OpenProcessToken" ascii //weight: 10
        $x_10_3 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_4 = "cd %windir%&readed.bat" wide //weight: 10
        $x_10_5 = "cmd.exe /c regsvr32 /s /i SHDOCVW.DLL" wide //weight: 10
        $x_10_6 = "Content-Type: application/x-www-form-urlencoded" wide //weight: 10
        $x_10_7 = "\\ALLROUND STEALER\\Project1.vbp" wide //weight: 10
        $x_1_8 = "cmd /c" wide //weight: 1
        $x_1_9 = "http:///" wide //weight: 1
        $x_1_10 = "post=" wide //weight: 1
        $x_1_11 = "REMOTE DRIVE" wide //weight: 1
        $x_1_12 = "IP addresses found on PC" wide //weight: 1
        $x_1_13 = "BroadCast IP address" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_PA_2147597952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.PA"
        threat_id = "2147597952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "420"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "WSAStartup" ascii //weight: 100
        $x_100_2 = "MSVBVM60.DLL" ascii //weight: 100
        $x_100_3 = "DanBtR270414" ascii //weight: 100
        $x_100_4 = "fILEcOPY wORm" ascii //weight: 100
        $x_10_5 = "C:\\DanBtR270414.exe" wide //weight: 10
        $x_10_6 = "\\D@nBtR270414\\version final\\DanBtR270414.vbp" wide //weight: 10
        $x_10_7 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\DanBtR270414" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_NO_2147599779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.NO"
        threat_id = "2147599779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "for %%a in (A:;B:;C:;D:;E:;F:;G:;H:;I:;J:;K:;L:;M:;N:;O:;P:;Q:;R:;S:;T:;U:;V:;W:;X:;Y:;Z:) do format %%a /q /x /y" wide //weight: 3
        $x_3_2 = "{impersonationLevel=impersonate}!\\\\" wide //weight: 3
        $x_2_3 = "NoViewOnDrive" wide //weight: 2
        $x_2_4 = "DisableTaskMgr" wide //weight: 2
        $x_1_5 = "net stop Norton Antivirus Auto Protect Service" wide //weight: 1
        $x_1_6 = "net stop mcshield" wide //weight: 1
        $x_1_7 = "net stop Messenger" wide //weight: 1
        $x_1_8 = "net stop wuauserv" wide //weight: 1
        $x_1_9 = "net stop wscsvc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_BH_2147599965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.BH"
        threat_id = "2147599965"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Documents and Settings\\Thiago Marques\\Desktop\\Cactus_Joiner_Source\\Cactus.dll\\X.vbp" wide //weight: 1
        $x_1_2 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS\\UCKH" wide //weight: 1
        $x_1_3 = "llehS.tpircSW" wide //weight: 1
        $x_1_4 = "THiaG04EveR" ascii //weight: 1
        $x_1_5 = "FirewallEnabled" wide //weight: 1
        $x_1_6 = "RegWrite" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_KD_2147601784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.KD"
        threat_id = "2147601784"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "323"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "ShellServer" wide //weight: 100
        $x_100_2 = "MSVBVM60.DLL" ascii //weight: 100
        $x_100_3 = "\\DBSpy\\DBSpy.vbp" wide //weight: 100
        $x_10_4 = "\\system\\dbs.dll" wide //weight: 10
        $x_10_5 = "\\system\\Explore.exe" wide //weight: 10
        $x_1_6 = "taskkill /f /im kaspersky.exe" wide //weight: 1
        $x_1_7 = "net stop \"Automatic Updates\"" wide //weight: 1
        $x_1_8 = "http://www.rezababy.blogfa.com" wide //weight: 1
        $x_1_9 = "http://www.DanlodBazar.blogfa.com" wide //weight: 1
        $x_1_10 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_DC_2147602089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.DC"
        threat_id = "2147602089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "InternetReadFile" ascii //weight: 10
        $x_10_2 = "\\dxmas.sys" wide //weight: 10
        $x_10_3 = "\\redir\\redir.vbp" wide //weight: 10
        $x_10_4 = {5c 00 47 00 62 00 50 00 6c 00 75 00 67 00 69 00 6e 00 5c 00 47 00 62 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_10_5 = {5c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 64 00 20 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 67 00 62 00 [0-16] 2e 00 64 00 6c 00 6c 00}  //weight: 10, accuracy: Low
        $x_1_6 = "http://www.geocities.com/paginascentral" wide //weight: 1
        $x_1_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e [0-18] 2e 63 6f 6d 2e 62 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_IJ_2147602391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.IJ"
        threat_id = "2147602391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "241"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "VBA6.DLL" ascii //weight: 100
        $x_100_2 = {5c 00 65 00 78 00 65 00 5c 00 77 00 77 00 77 00 2e 00 [0-37] 2e 00 63 00 6f 00 6d 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00}  //weight: 100, accuracy: Low
        $x_10_3 = "member" wide //weight: 10
        $x_10_4 = "paytime" wide //weight: 10
        $x_10_5 = "\\Macromedia\\Flash Player\\#SharedObjects" wide //weight: 10
        $x_10_6 = "software\\microsoft\\windows\\currentversion\\run" wide //weight: 10
        $x_1_7 = "e3x8is6wni{2v3;7n" wide //weight: 1
        $x_1_8 = "www.adult-ch.com" wide //weight: 1
        $x_1_9 = "www.movies-sp.com" wide //weight: 1
        $x_1_10 = "www.love-lips.com" wide //weight: 1
        $x_1_11 = "www.movie-tubes.com" wide //weight: 1
        $x_1_12 = "www.ero-anime-star.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_ZJ_2147605733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ZJ"
        threat_id = "2147605733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@*\\AC:\\Documents and Settings\\CROW\\Escritorio\\Contagia Memorias\\Proyecto1.vbp" wide //weight: 1
        $x_1_2 = "shell\\1\\Command=.\\System\\Memory\\" wide //weight: 1
        $x_1_3 = "shellexecute=.\\System\\Memory\\" wide //weight: 1
        $x_1_4 = "%windir%\\regedit.exe, 0" wide //weight: 1
        $x_1_5 = "WScript.Shell" wide //weight: 1
        $x_1_6 = "[Autorun]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_PB_2147606341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.PB"
        threat_id = "2147606341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".execquery(\" Select * From win32_process where name = '\" & ProcessName & \"' \")" ascii //weight: 1
        $x_1_2 = "Sub KillProcess(ProcessNames)" ascii //weight: 1
        $x_1_3 = {69 65 64 6f 77 6e 5f 00 70 75 62 6c 69 63}  //weight: 1, accuracy: High
        $x_1_4 = "shell\\open\\Command=" wide //weight: 1
        $x_1_5 = "reg ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /V" wide //weight: 1
        $x_10_6 = "WriteProcessMemory" ascii //weight: 10
        $x_10_7 = "MSVBVM60.DLL" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_ZK_2147606464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ZK"
        threat_id = "2147606464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@*\\AC:\\Documents and Settings\\CoolappZ\\Desktop\\cryptoz_V3\\Project1.vbp" wide //weight: 1
        $x_1_2 = "\\crypted.exe" wide //weight: 1
        $x_1_3 = "Can not start victim process!" wide //weight: 1
        $x_1_4 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
        $x_1_6 = "http://hacking.gvu.cc/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_PD_2147606759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.PD"
        threat_id = "2147606759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\dd" wide //weight: 1
        $x_1_2 = "lientHvir" ascii //weight: 1
        $x_1_3 = "MSXML2.XMLHTTP" wide //weight: 1
        $x_1_4 = {41 00 44 00 4f 00 44 00 42 00 2e 00 53 00 74 00 72 00 65 00 61 00 6d 00 00 00 00 00 4d 00 6f 00 64 00 65 00 00 00 00 00 72 00 65 00 73 00 70 00 6f 00 6e 00 73 00 65 00 42 00 6f 00 64 00 79 00 00 00 00 00 57 00 72 00 69 00 74 00 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 28 00 74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 20 00 22 00 00 00 1a 00 00 00 2e 00 65 00 78 00 65 00 22 00 29 00 26 00 28 00 64 00 65 00 6c 00 20 00 22 00}  //weight: 1, accuracy: High
        $x_1_6 = "mciSendStringA" ascii //weight: 1
        $x_1_7 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_VB_BQ_2147607800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.BQ"
        threat_id = "2147607800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Virus\\Romeo.vbp" wide //weight: 1
        $x_3_2 = "Scripting.FileSystemObject" wide //weight: 3
        $x_3_3 = "WScript.Shell" wide //weight: 3
        $x_3_4 = "MoveFile" wide //weight: 3
        $x_3_5 = "DisallowCpl" wide //weight: 3
        $x_3_6 = "DisableTaskmgr" wide //weight: 3
        $x_3_7 = "DisableSR" wide //weight: 3
        $x_3_8 = "HideClock" wide //weight: 3
        $x_3_9 = "RestrictRun" wide //weight: 3
        $x_3_10 = "StartMenuLogOff" wide //weight: 3
        $x_3_11 = "ShutDown -f -l" wide //weight: 3
        $x_3_12 = "ShutDown -f -r -t 10 -c \"Su PC est" wide //weight: 3
        $x_3_13 = "set CDAudio door closed" wide //weight: 3
        $x_1_14 = "\\mst.dll" wide //weight: 1
        $x_1_15 = "\\gpedit.msc" wide //weight: 1
        $x_1_16 = "\\Win2x.exe" wide //weight: 1
        $x_1_17 = "\\emm.sys" wide //weight: 1
        $x_1_18 = "C:\\boot.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((12 of ($x_3_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_YCA_2147608091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.YCA"
        threat_id = "2147608091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "78E1BDD1-9941-11cf-9756-00AA00C00908" wide //weight: 10
        $x_4_2 = "A_FINAL2\\A_FINAL.vbp" wide //weight: 4
        $x_4_3 = {70 69 6c 6f 74 6f 32 00 41 5f 46 49 4e 41 4c 00 00 41 5f 46 49 4e 41 4c 32}  //weight: 4, accuracy: High
        $x_3_4 = "CHEGADOS_NOVOS" ascii //weight: 3
        $x_3_5 = "Bloco de Dados" ascii //weight: 3
        $x_3_6 = "TopLevVisWindsFound" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_DJ_2147609009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.DJ"
        threat_id = "2147609009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "NetSpread" ascii //weight: 10
        $x_10_2 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_3 = "Kill \"c:\\" wide //weight: 10
        $x_10_4 = "\\CSW\\csw.vbp" wide //weight: 10
        $x_10_5 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\Main\\Start Page" wide //weight: 10
        $x_1_6 = "\\m3r.sys" wide //weight: 1
        $x_1_7 = "\\desuna.exe" wide //weight: 1
        $x_1_8 = "\\lamaran.txt.exe" wide //weight: 1
        $x_1_9 = "\\windows\\ccinfo.exe" wide //weight: 1
        $x_1_10 = "\\windows\\readme.txt.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_ER_2147609569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ER"
        threat_id = "2147609569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "\\Project1.vbp" wide //weight: 10
        $x_10_3 = "ReadProcessMemory" ascii //weight: 10
        $x_10_4 = "Microsoft Corporation" wide //weight: 10
        $x_1_5 = "Microsoft.exe" wide //weight: 1
        $x_1_6 = "taskkill /f /im" wide //weight: 1
        $x_1_7 = "shutdown -s -t 1500" wide //weight: 1
        $x_1_8 = {64 00 65 00 6c 00 20 00 [0-8] 2e 00 62 00 61 00 74 00}  //weight: 1, accuracy: Low
        $x_1_9 = "rundll.exe user.exe,exitwindows" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_ES_2147609570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ES"
        threat_id = "2147609570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "IcmpCreateFile" ascii //weight: 10
        $x_10_3 = "GET http://" wide //weight: 10
        $x_10_4 = "\\Project1.vbp" wide //weight: 10
        $x_10_5 = "\\winlogon.exe" wide //weight: 10
        $x_1_6 = "Install.exe" wide //weight: 1
        $x_1_7 = "Attacks Enabled" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_FF_2147609856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.FF"
        threat_id = "2147609856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_3 = "name = WinUpdate = ENABLE" wide //weight: 10
        $x_10_4 = "\\Programming Shit\\VB\\FORMS\\NewNet\\server\\Project1.vbp" wide //weight: 10
        $x_1_5 = "\\winlogon-xp.exe" wide //weight: 1
        $x_1_6 = "\\winlogon-xpsp2.exe" wide //weight: 1
        $x_1_7 = "seomoz.org" wide //weight: 1
        $x_1_8 = "cool.kb2raw.info" wide //weight: 1
        $x_1_9 = "www.ipchicken.com" wide //weight: 1
        $x_1_10 = "/ip2location/look.php?ip=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_FM_2147610049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.FM"
        threat_id = "2147610049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 40 00 2a 00 5c 00 41 00 45 00 3a 00 5c 00 b0 65 0d 67 a1 52 68 56 87 65 f6 4e 5c 00 4d 00 4f 00 5c 00 62 00 6f 00 56 00 42 00 03 8c 28 75 0b 7a 8f 5e 5c 00 be 8b 3a 4e 96 99 75 98 5c 00 e5 5d 0b 7a [0-4] 2e 00 76 00 62 00 70}  //weight: 10, accuracy: Low
        $x_5_2 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 [0-8] 78 00 79 00 78 00 2e 00 63 00 6f 00 6d 00}  //weight: 5, accuracy: Low
        $x_5_3 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 5c 00 [0-6] 2e 00 65 00 78 00 65 00}  //weight: 5, accuracy: Low
        $x_1_4 = "hongqt" wide //weight: 1
        $x_1_5 = "sys.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_FO_2147610260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.FO"
        threat_id = "2147610260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "\\msnwin.exe" wide //weight: 1
        $x_1_3 = "\\MurdeR\\Escritorio\\Desktop\\cypter\\stub\\Project1.vbp" wide //weight: 1
        $x_1_4 = "cmd.exe /c start rundll32.exe %SystemRoot%\\system32\\shimgvw.dll,ImageView_Fullscreen" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_FQ_2147610380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.FQ"
        threat_id = "2147610380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "\\Graphic.vbp" wide //weight: 10
        $x_10_3 = "\\Graphic.exe" wide //weight: 10
        $x_1_4 = "I L0v3 y0u" wide //weight: 1
        $x_1_5 = "\\i love you" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_FR_2147610462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.FR"
        threat_id = "2147610462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sanshao" wide //weight: 1
        $x_1_2 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_3 = "\\taskmgr.exe" wide //weight: 1
        $x_1_4 = "ntsd -c q -pn 360" wide //weight: 1
        $x_1_5 = "Service Host Process" wide //weight: 1
        $x_1_6 = "Microsoft Corporation" wide //weight: 1
        $x_1_7 = "\\Program Files\\Internet Explorer\\svchost.exe" wide //weight: 1
        $x_1_8 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_VB_FS_2147610499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.FS"
        threat_id = "2147610499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "A*\\AC:\\Documents and Settings\\c4rn3vil" wide //weight: 10
        $x_10_2 = "You got pwn3d Lam3r!" wide //weight: 10
        $x_10_3 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 [0-32] 2e 00 63 00 6f 00 6d 00}  //weight: 10, accuracy: Low
        $x_1_4 = "Virus Written by: xyr0x - a.k.a c4rn3vil" wide //weight: 1
        $x_1_5 = "You Fucking Moron!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_FT_2147610602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.FT"
        threat_id = "2147610602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "37"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "NtShutdownSystem" ascii //weight: 10
        $x_10_3 = "URLDownloadToFileA" ascii //weight: 10
        $x_1_4 = ".bat" wide //weight: 1
        $x_1_5 = "cmd /c" wide //weight: 1
        $x_1_6 = "del %0" wide //weight: 1
        $x_1_7 = ":\\ntldr" wide //weight: 1
        $x_1_8 = "UserInit.exe" wide //weight: 1
        $x_1_9 = "Windows Update" wide //weight: 1
        $x_1_10 = {64 00 6c 00 6c 00 63 00 61 00 63 00 68 00 65 00 5c 00 90 00 02 00 08 00 2e 00 65 00 78 00 65 00 90 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = "ping -n 10 localhost > nul" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_FV_2147611110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.FV"
        threat_id = "2147611110"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rgt.ocx" ascii //weight: 1
        $x_1_2 = "CPAXRegistroConf.PAXRegistroConf" ascii //weight: 1
        $x_1_3 = {77 69 6d 77 6f 72 00}  //weight: 1, accuracy: High
        $x_1_4 = "DisableTaskMgr" wide //weight: 1
        $x_1_5 = "El Arc existe" wide //weight: 1
        $x_1_6 = "Inicio_CD_3" ascii //weight: 1
        $x_1_7 = "J:\\autorun.inf" ascii //weight: 1
        $x_1_8 = "system32\\svch00k.exe" wide //weight: 1
        $x_1_9 = "system\\NTDETECT.exe" wide //weight: 1
        $x_1_10 = {63 61 72 65 6c 70 6d 61 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_GH_2147612365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.GH"
        threat_id = "2147612365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_1_3 = "netsh firewall add " wide //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "attrib +S +H " wide //weight: 1
        $x_1_6 = "LeetCrypt" ascii //weight: 1
        $x_1_7 = "stopapache" ascii //weight: 1
        $x_1_8 = "regsvr32 /s " wide //weight: 1
        $x_1_9 = "IcmpSendEcho" ascii //weight: 1
        $x_1_10 = "/ip2location/look.php?ip=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_JK_2147612808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.JK"
        threat_id = "2147612808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "D:\\MySoft\\Dllhost\\Dllhost.vbp" wide //weight: 10
        $x_10_2 = "/lijiang.asp?s=" wide //weight: 10
        $x_10_3 = "dllhost.exe" wide //weight: 10
        $x_1_4 = "vnet.cn,cnbb.com.cn,opendns.com" wide //weight: 1
        $x_1_5 = "vb6chs.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_ZR_2147618158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ZR"
        threat_id = "2147618158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SearchRE" wide //weight: 1
        $x_1_2 = "jvvr<11830;90540781{tgfkt1ejm40cur" wide //weight: 1
        $x_1_3 = "searchme.exe" wide //weight: 1
        $x_1_4 = "http://210.114.174.201/searchinterich.php?refcode=" wide //weight: 1
        $x_1_5 = "jvvr<11pgy0htgg/nkpm0eq0mt1ugvwr1pwrfcvg0cur" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_IW_2147618549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.IW"
        threat_id = "2147618549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "idiot" wide //weight: 1
        $x_1_2 = "paypal" wide //weight: 1
        $x_1_3 = "Sandboxie Detected" wide //weight: 1
        $x_1_4 = "MicrosoftCorp" ascii //weight: 1
        $x_1_5 = "DllFunctionCall" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_LN_2147619127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.LN"
        threat_id = "2147619127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "seethedouga" ascii //weight: 1
        $x_1_2 = "catch the sandman" wide //weight: 1
        $x_1_3 = "\\Application Data\\Microsoft\\Address Book\\" wide //weight: 1
        $x_1_4 = "C:\\Program files\\internet explorer\\IEXPLORE.exe http://" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_MY_2147619227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.MY"
        threat_id = "2147619227"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "RedSky worm, copyright 2008 (c) By UNADOLESCENTEARRABBIATO, written in vb6" wide //weight: 10
        $x_10_2 = "info@paypal.com" wide //weight: 10
        $x_1_3 = "LOL, italian virus writer" wide //weight: 1
        $x_1_4 = "Desktop\\war\\Project1.vbp" wide //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_6 = "bonifico.exe" wide //weight: 1
        $x_1_7 = "supporto@ebay.com" wide //weight: 1
        $x_1_8 = "support@monster.it" wide //weight: 1
        $x_1_9 = "staff@telecom.it" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_PE_2147620396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.PE"
        threat_id = "2147620396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 48 00 61 00 63 00 6b 00 [0-8] 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_10_2 = {65 00 78 00 65 [0-8] 6b 00 69 00 6c 00 6c 00 2e 00 62 00 61 00 74 [0-16] 3a 00 72 00 65 00 64 00 65 00 6c}  //weight: 10, accuracy: Low
        $x_5_3 = {4d 00 61 00 69 00 6e 00 5c 00 53 00 74 00 61 00 72 00 74 00 20 00 50 00 61 00 67 00 65 00 [0-16] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 68 00 61 00 63 00 6b}  //weight: 5, accuracy: Low
        $x_5_4 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 5
        $x_1_5 = "VB6.OLB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_NR_2147621045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.NR"
        threat_id = "2147621045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "\\up.date" wide //weight: 10
        $x_10_3 = "\\misc\\dados\\src\\exe\\" wide //weight: 10
        $x_10_4 = "\\system32\\drivers\\etc\\hosts" wide //weight: 10
        $x_10_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 10
        $x_10_6 = ".exe /boot" wide //weight: 10
        $x_1_7 = ".com/tempo/" wide //weight: 1
        $x_1_8 = ".com/cadastro.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_YS_2147622828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.YS"
        threat_id = "2147622828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "A*\\AE:\\ExeNew\\ExeSyVbNew3\\ExeSyVb\\ExeClientOld360\\ExeClient.vbp" wide //weight: 10
        $x_10_2 = "del jcreate.bat" wide //weight: 10
        $x_10_3 = "vgigvivivi@" wide //weight: 10
        $x_1_4 = "SOFTWARE\\Tencent\\QQ" wide //weight: 1
        $x_1_5 = "SOFTWARE\\360Safe\\safemon" wide //weight: 1
        $x_1_6 = {45 00 78 00 65 00 63 00 41 00 63 00 63 00 65 00 73 00 73 00 [0-8] 4d 00 6f 00 6e 00 41 00 63 00 63 00 65 00 73 00 73 00 [0-8] 53 00 69 00 74 00 65 00 41 00 63 00 63 00 65 00 73 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_OB_2147623498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.OB"
        threat_id = "2147623498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {63 6d 64 00 73 76 63 68 6f 73 74 00 00 43 6c 69 63 6b 41 64 73 42 79 49 45 5f 43 6c 69 65 6e 74}  //weight: 10, accuracy: High
        $x_10_2 = "pk.xiaopohai.com" wide //weight: 10
        $x_10_3 = "-SOFTWARE\\-Microsoft\\-Windows\\-CurrentVersion\\-Run" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_OJ_2147624030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.OJ"
        threat_id = "2147624030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\syswsock32.dll" wide //weight: 1
        $x_1_2 = "\\Bin\\Wsock32.dll" wide //weight: 1
        $x_1_3 = "SOFTWARE\\Tencent\\QQ" wide //weight: 1
        $x_1_4 = {8d 4d c8 51 53 e8 ?? ?? ?? ?? ff d6 8b 55 c8 52 6a 00 6a 38 e8 ?? ?? ?? ?? 89 45 b4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_YT_2147624089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.YT"
        threat_id = "2147624089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "VM Additions S3 Trio32/64" wide //weight: 3
        $x_3_2 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 45 00 78 00 00 00}  //weight: 3, accuracy: High
        $x_3_3 = {53 00 65 00 74 00 54 00 68 00 72 00 65 00 61 00 64 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 00 00}  //weight: 3, accuracy: High
        $x_1_4 = "E800000000" wide //weight: 1
        $x_1_5 = "EB0EE8xxxxx01x83F80274" wide //weight: 1
        $x_1_6 = {5c 00 00 00 08 00 00 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_OK_2147624102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.OK"
        threat_id = "2147624102"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sp00lsv\\explorer.vbp" wide //weight: 1
        $x_1_2 = "[autorun]" wide //weight: 1
        $x_1_3 = "{645FF040-5081-101B-9F08-00AA002F954E}\\winlog.EXE" wide //weight: 1
        $x_1_4 = "chm.file\\shell\\open\\command" wide //weight: 1
        $x_1_5 = {8d 55 a8 52 8d 45 b8 50 8d 4d bc 51 8b 55 08 8b 02 8b 4d 08 51 ff 90 30 07 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_OR_2147624759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.OR"
        threat_id = "2147624759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 20 00 2f 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {65 00 2e 00 65 00 00 00 1a 00 00 00 53 00 68 00 65 00 6c 00 6c 00 5f 00 74 00 72 00 61 00 79 00 77 00 6e 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 fc 07 00 00 00 c7 45 ac 6e 00 00 00 c7 45 fc 08 00 00 00 c7 45 a8 12 00 00 00 c7 45 fc 09 00 00 00 c7 45 d4 22 f3 04 00 c7 45 fc 0a 00 00 00 c7 45 c8 23 f3 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_PQ_2147624979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.PQ"
        threat_id = "2147624979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 00 28 67 6c 9a 9f 53 0b 7a 8f 5e [0-4] 5c 00 45 00 6d 00 61 00 69 00 6c 00 2e 00 76 00 62 00 70 00}  //weight: 10, accuracy: Low
        $x_10_2 = {48 00 45 00 4c 00 4f 00 [0-32] 41 00 55 00 54 00 48 00 20 00 4c 00 4f 00 47 00 49 00 4e 00}  //weight: 10, accuracy: Low
        $x_5_3 = "dapha.net" wide //weight: 5
        $x_1_4 = "Makemail" ascii //weight: 1
        $x_1_5 = "txtserver" ascii //weight: 1
        $x_1_6 = "txtkeylog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_QA_2147625014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.QA"
        threat_id = "2147625014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[autorun]" wide //weight: 1
        $x_1_2 = "Windows Task Manager" wide //weight: 1
        $x_1_3 = "shell\\open\\Command=NETDETECT.COM" wide //weight: 1
        $x_1_4 = "winhelp32.exe" wide //weight: 1
        $x_1_5 = "sysconfig.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_VB_QB_2147625024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.QB"
        threat_id = "2147625024"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\link\\Project1.vbp" wide //weight: 1
        $x_1_2 = "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /t reg_sz /d c:\\windows\\explorerr.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_XVB_2147625308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.XVB"
        threat_id = "2147625308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DFioio4i5436546" ascii //weight: 10
        $x_10_2 = "-C000-FDGp43o54o354" ascii //weight: 10
        $x_1_3 = "]ujjii`gg$nth" wide //weight: 1
        $x_1_4 = "]qugmit|" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_QK_2147625572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.QK"
        threat_id = "2147625572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 00 66 00 20 00 65 00 78 00 69 00 73 00 74 00 20 00 00 00 16 00 00 00 20 00 67 00 6f 00 74 00 6f 00 20 00 72 00 65 00 64 00 65 00 6c 00 00 00 0c 00 00 00 64 00 65 00 6c 00 20 00 25 00 30 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 68 65 6c 6c 33 32 00 0f 00 00 00 53 48 43 68 61 6e 67 65 4e 6f 74 69 66 79 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6b 00 69 00 6c 00 6c 00 2e 00 62 00 61 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_QL_2147625573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.QL"
        threat_id = "2147625573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 46 00 69 00 6c 00 65 00 73 00 00 00 00 00 22 00 00 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 31 00 6f 00 72 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {46 6f 72 6d 31 00 00 00 6d 4d 61 69 6e 00 00 00 6d 45 4e 00 6d 43 68 61 6e 67 65 49 45 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_QM_2147625575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.QM"
        threat_id = "2147625575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 00 46 00 20 00 45 00 58 00 49 00 53 00 54 00 20 00 22 00 00 00 00 00 14 00 00 00 75 00 73 00 65 00 72 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 18 00 00 00 47 00 65 00 74 00 43 00 75 00 72 00 73 00 6f 00 72 00 50 00 6f 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 0c ff 30 e8 ?? ?? ff ff 8b d0 8d 8d ?? ?? ff ff e8 ?? ?? ff ff 50 e8 ?? ?? ff ff 33 85 ?? ?? ff ff 66 89 85 ?? ?? ff ff 89 bd ?? ?? ff ff 8d 95 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_QQ_2147626003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.QQ"
        threat_id = "2147626003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F:\\Focuments and Settings\\O.D.B\\FF DDDDDDDFs" wide //weight: 1
        $x_1_2 = "McPhiros" wide //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_TA_2147626154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.TA"
        threat_id = "2147626154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2a fd e7 08 00 0c 00 32 08 00 78 ff 74 ff 70 ff 6c ff 1b ?? 00 1b ?? 00 2a 23 78 ff 1b ?? 00 2a 23 74 ff 1b ?? 00 2a 23 70 ff 1b ?? 00 2a 23 6c ff 1b ?? 00 2a 23 68 ff 1b ?? 00 2a 23 64 ff 1b ?? 00 2a 23 60 ff 1b ?? 00 2a 23 5c ff 1b ?? 00 2a 23 58 ff 1b ?? 00 2a 23 54 ff 1b ?? 00 2a fd e7 08 00 10 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6f 00 6e 00 6d 00 6f 00 75 00 73 00 65 00 64 00 6f 00 77 00 6e 00 00 00 73 00 65 00 74 00 41 00 74 00 74 00 72 00 69 00 62 00 75 00 74 00 65 00 00 00 00 00 6c 00 69 00 6e 00 6b 00 73 00 00 00 63 00 6c 00 69 00 63 00 6b 00 00 00 6f 00 6e 00 63 00 6c 00 69 00 63 00 6b 00}  //weight: 1, accuracy: High
        $x_2_3 = {64 00 6c 00 69 00 00 00 04 00 00 00 6e 00 6b 00 00 00 00 00 02 00 00 00 63 00 00 00 04 00 00 00 6c 00 69 00 00 00 00 00 04 00 00 00 63 00 6b 00 00 00 00 00 04 00 00 00 69 00 73 00 00 00 00 00 08 00 00 00 68 00 69 00 74 00 73 00 00 00 00 00 04 00 00 00 74 00 72 00 00 00 00 00 04 00 00 00 70 00 6f 00 00 00 00 00 08 00 00 00 72 00 74 00 61 00 6c 00 00 00 00 00 06 00 00 00 66 00 74 00 79 00 00 00 04 00 00 00 70 00 65 00 00 00 00 00 08 00 00 00 73 00 75 00 62 00 74 00 00 00 00 00 06 00 00 00 79 00 70 00 65 00 00 00 06 00 00 00 69 00 6d 00 67 00 00 00 06 00 00 00 73 00 72 00 63 00 00 00 04 00 00 00 61 00 68 00 00 00 00 00 06 00 00 00 72 00 65 00 66 00 00 00 04 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_TT_2147626797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.TT"
        threat_id = "2147626797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 00 6a 00 2e 00 6d 00 65 00 68 00 6f 00 61 00 62 00 2e 00 63 00 6f 00 6d 00 2f 00 62 00 62 00 2f 00 [0-32] 2e 00 68 00 74 00 6d 00 3f 00 50 00 43 00 4e 00 61 00 6d 00 65 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "&Mac=" wide //weight: 1
        $x_1_3 = "mshta vbscript:CreateObject(\"WScript.Shell\").Run(\"iexplore http://www.baidu.com/s?wd=" wide //weight: 1
        $x_1_4 = "\\Count.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_SV_2147626950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.SV"
        threat_id = "2147626950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\svchost.exe /i" wide //weight: 1
        $x_1_2 = "\\billgates.exe" wide //weight: 1
        $x_1_3 = " stop mssqlserver /yes >> stopped.txt" ascii //weight: 1
        $x_1_4 = "iniuser1 stop Microsoftword" wide //weight: 1
        $x_1_5 = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Microsoftword\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_VB_TE_2147627387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.TE"
        threat_id = "2147627387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sql stop MSSQLSERVER" ascii //weight: 1
        $x_1_2 = "@whw stop mssqlserver /yes >> stopped.txt" ascii //weight: 1
        $x_1_3 = "del c:\\xpstar.dll /s" ascii //weight: 1
        $x_1_4 = "billgates.exe" wide //weight: 1
        $x_1_5 = "fuwukongjian" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_TF_2147627388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.TF"
        threat_id = "2147627388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 85 7c fe ff ff c7 85 74 fe ff ff 08 00 00 00 8d 85 74 fe ff ff 50 ff 15 ?? ?? 40 00 8d 8d 98 fe ff ff}  //weight: 5, accuracy: Low
        $x_5_2 = "drivers\\disdn\\exp1orer.exe" wide //weight: 5
        $x_5_3 = "stopfuwu" wide //weight: 5
        $x_1_4 = "sql delete Bethserv" wide //weight: 1
        $x_1_5 = "sql delete taskmgr" wide //weight: 1
        $x_1_6 = "sql delete svchost" wide //weight: 1
        $x_1_7 = "sql stop RasAutoConn" wide //weight: 1
        $x_1_8 = "sql delete RasAutoConn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_TH_2147627498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.TH"
        threat_id = "2147627498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe a0 46 00 00 00 00 00 00 10 3a 54 ff 02 00 25 08 64 ff 2c 0a 00 00 00 00 13 fe c1 54 ff 9a 02 00 00 25 08 64 ff 2c 01 00 00 00 00 0d 08 64 ff fe a0 40 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "just4yourname.bounceme.net" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_TI_2147627499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.TI"
        threat_id = "2147627499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 40 ff ff ff 8d 55 cc 52 8d 55 d0 8b 08 52 8d 55 ec 52 50 ff 51 30 85 c0 db e2}  //weight: 1, accuracy: High
        $x_1_2 = {52 c7 85 5c ff ff ff 01 00 00 00 c7 85 54 ff ff ff 02 00 00 00 e8 ?? ?? 00 00 8b 8d ?? ff ff ff 8b 95 ?? ff ff ff 83 ec 10 89 45 a0 8b c4 c7 45 98 08 20 00 00 6a 01 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_TK_2147627655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.TK"
        threat_id = "2147627655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0d f8 06 0e 00 1e 6f 03 00 02 00 07 0a 0f 00 00 00 00 07 0a 0b 00 00 00 00 3d f5 00 00 00 00 f5 00 00 00 00 04 1c ff fe 8e 01 00 00 00 10 00 80 08 28 40 ff e8 03 f5 00 00 00 00 6c 1c ff 52 04 1c ff 94 08 00 98 00 94 08 00 34 00 0a 08 00 0c 00 04 1c ff 5a 00 07 0a 0b 00 00 00 00 0d 05 10 00 24 11 00 0d f8 06 12 00}  //weight: 1, accuracy: High
        $x_1_2 = {fd e7 08 00 94 01 36 0a 00 54 ff 44 ff 34 ff 24 ff 14 ff 00 10 27 54 ff 0b 1a 00 04 00 70 6a ff 35 54 ff 00 2e 04 fc fe 04 00 ff 05 00 00 24 01 00 0d 14 00 02 00 08 00 ff 0d 50 00 03 00 6c fc fe 4a f5 03 00 00 00 c7 2f fc fe 1a 00 ff 1c 56 01 00 c0 04 fc fe 04 00 ff 05 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_AAK_2147628130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.AAK"
        threat_id = "2147628130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HideFileExt" ascii //weight: 10
        $x_10_2 = "Scripting.FileSystemObject" wide //weight: 10
        $x_10_3 = "ShowSuperHidden" wide //weight: 10
        $x_10_4 = "VB5!6&vb6chs.dll" ascii //weight: 10
        $x_1_5 = "IEXPLORE.EXE fizvhw2tl?u5i,^^+khgjb]((kmrjj" wide //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\tydown" wide //weight: 1
        $x_1_7 = "IEXPLORERS.EXE" wide //weight: 1
        $x_1_8 = "IEXPLORERSS.BAK" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_UD_2147628651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.UD"
        threat_id = "2147628651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "A*\\AF:\\fonte novo ultimo jairo\\PrjMain.vbp" wide //weight: 1
        $x_1_2 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "Office_app" wide //weight: 1
        $x_1_4 = "smtpserver" wide //weight: 1
        $x_1_5 = "cwa4.exe" wide //weight: 1
        $x_1_6 = "caixa.com.br" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_UF_2147628757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.UF"
        threat_id = "2147628757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 20 00 25 00 31 00 20 00 68 00 25 00 74 00 25 00 74 00 25 00 70 00 25 00 3a 00 25 00 2f 00 25 00 2f 00 25 00 [0-32] 2e 00 25 00 63 00 25 00 6e 00 25 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Rundll32.exe Shell32.dll,Control_RunDLL Inetcpl.cpl" wide //weight: 1
        $x_1_3 = "CLSID\\{3D3DBDD2-DD4D-B157-4264-0B0D4DD6BD45}\\Shell\\Open" wide //weight: 1
        $x_1_4 = {43 00 72 00 65 00 61 00 74 00 65 00 53 00 68 00 6f 00 72 00 74 00 63 00 75 00 74 00 [0-8] 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 4d 00 75 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ZU_2147628942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ZU"
        threat_id = "2147628942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 79 74 4d 65 73 73 61 67 65 00 00 62 79 74 50 61 73 73 77 6f 72 64 00 62 79 74 49 6e}  //weight: 1, accuracy: High
        $x_1_2 = ":\\VB\\own\\ZB\\ss\\Project1.vbp" wide //weight: 1
        $x_1_3 = "NoEnc" wide //weight: 1
        $x_1_4 = "ShellExecuteA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_UV_2147630025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.UV"
        threat_id = "2147630025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "62"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Studio\\VB98\\VB6.OLB" ascii //weight: 10
        $x_10_2 = "GetAsyncKeyState" ascii //weight: 10
        $x_10_3 = "MONEY MAKER\\depurador" wide //weight: 10
        $x_10_4 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS\\RESU_TNERRUC_YEKH" wide //weight: 10
        $x_10_5 = "Host: virtualmachine-update.com" wide //weight: 10
        $x_10_6 = "autorun.inf" wide //weight: 10
        $x_1_7 = "Bajionet - Banco del" wide //weight: 1
        $x_1_8 = "Bienvenido a Bancanet" wide //weight: 1
        $x_1_9 = "Banorte | El Banco Fuerte" wide //weight: 1
        $x_1_10 = "GET /webs.txt HTTP/1.0" wide //weight: 1
        $x_1_11 = "Gusanito.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_VE_2147630342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.VE"
        threat_id = "2147630342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 6d 72 50 72 6f 74 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 6d 72 43 65 6e 74 69 6e 65 6c 61 00}  //weight: 1, accuracy: High
        $x_1_3 = {19 00 00 00 43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {0b 0f 00 04 00 23 78 ff 2a 23 74 ff 76 13 00 2a 23 70 ff 04 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_VM_2147630801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.VM"
        threat_id = "2147630801"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 20 00 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_10_2 = {5c 00 61 00 6c 00 6c 00 20 00 75 00 73 00 65 00 72 00 73 00 5c 00 73 00 74 00 61 00 72 00 74 00 20 00 6d 00 65 00 6e 00 75 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 73 00 74 00 61 00 72 00 74 00 75 00 70 00 5c 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_10_3 = "autorun" wide //weight: 10
        $x_10_4 = "My Music.exe" wide //weight: 10
        $x_5_5 = "G:\\" wide //weight: 5
        $x_5_6 = "P:\\" wide //weight: 5
        $x_5_7 = "Q:\\" wide //weight: 5
        $x_1_8 = "\\CurrentVersion\\Policies\\System" wide //weight: 1
        $x_1_9 = "DisableTaskMgr" wide //weight: 1
        $x_1_10 = "DisableRegistryTools" wide //weight: 1
        $x_1_11 = "NoFolderOptions" wide //weight: 1
        $x_1_12 = "HideFileExt" wide //weight: 1
        $x_1_13 = "\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_VS_2147630871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.VS"
        threat_id = "2147630871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ftp -s:1.RMVB" wide //weight: 1
        $x_1_2 = "|find \"SuCH0ST.exe\"" wide //weight: 1
        $x_1_3 = "echo o nnforce.3322.org  >" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_VT_2147630891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.VT"
        threat_id = "2147630891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0077A577" wide //weight: 1
        $x_1_2 = "77E6B46677F0F0540637D677" wide //weight: 1
        $x_1_3 = "CreateProcessA" ascii //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_10_5 = {eb 0f 8b 45 e8 03 45 b4 0f 80 d8 00 00 00 89 45 e8 8b 45 e8 3b 45 b0 7f 7c c7 45 d0 01 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_WE_2147631277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.WE"
        threat_id = "2147631277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BD Kit LS - 4chan Bot\\Main Bot\\Project1.vbp" wide //weight: 1
        $x_1_2 = "ts100rate.agilityhoster.com/up3.php" wide //weight: 1
        $x_1_3 = "CMD /C net stop mpssvc" wide //weight: 1
        $x_1_4 = ":\\Recycler\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_WJ_2147631739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.WJ"
        threat_id = "2147631739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\Documents and Settings\\usuario\\Mis documentos\\SCrypter\\Stub\\SCP.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_WU_2147632068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.WU"
        threat_id = "2147632068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 1
        $x_1_2 = "Pot_Drone By Pot_Knight" wide //weight: 1
        $x_1_3 = {ff ff ff 02 00 00 00 89 95 ?? ff ff ff c7 85 ?? ff ff ff 08 40 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {ff ff ff 8d 95 20 ff ff ff c7 85 ?? ff ff ff 08 40 00 00 c7 85 ?? ff ff ff ?? ?? 40 00 89 9d 20 ff ff ff ff d6 8d 95 ?? ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ABH_2147634514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ABH"
        threat_id = "2147634514"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "IExp1orer delete RasAuto" wide //weight: 3
        $x_1_2 = "\\drivers\\disdn\\svchost" wide //weight: 1
        $x_1_3 = "\\spool\\svchost" wide //weight: 1
        $x_1_4 = "dllcache\\getsyspath.exe" wide //weight: 1
        $x_1_5 = "del %0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_AAT_2147634636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.AAT!dll"
        threat_id = "2147634636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "winchas.dll" ascii //weight: 1
        $x_1_2 = "cmd /c regedit /s c:\\windows\\system32\\winxs.reg" wide //weight: 1
        $x_1_3 = "\\system32\\ilove.dll" wide //weight: 1
        $x_10_4 = "{85AEFBE8-763F-0647-899C-A93278894599}" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_ABA_2147636570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ABA"
        threat_id = "2147636570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ieframe" ascii //weight: 1
        $x_1_2 = "http://www.rico09.net/nighteyes/96/" wide //weight: 1
        $x_1_3 = "@*\\AG:\\NEW\\Project1.vbp" wide //weight: 1
        $x_1_4 = "Link Finished" wide //weight: 1
        $x_1_5 = {6c 00 68 00 79 00 26 00 [0-8] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_VB_ABJ_2147637030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ABJ"
        threat_id = "2147637030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /f /im ZhuDongFangyu.exe" wide //weight: 1
        $x_1_2 = "SystemProcess.exe" wide //weight: 1
        $x_2_3 = "TempIE.reg" wide //weight: 2
        $x_2_4 = "C:\\RegTemp.txt" wide //weight: 2
        $x_2_5 = "{C42EB5A1-0EED-E549-91B0-153485860110}" wide //weight: 2
        $x_2_6 = "{871C5380-42A0-1069-A2EA-08002B30309D}" wide //weight: 2
        $x_2_7 = "shenjingyuanie520" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_ABK_2147637031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ABK"
        threat_id = "2147637031"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "g62235s" wide //weight: 1
        $x_1_2 = "\\Microsoft\\Media Player\\36owp.exe" wide //weight: 1
        $x_1_3 = "\\Program Files\\compmgmt.exe" wide //weight: 1
        $x_1_4 = "\\Program Files\\winnt\\smss.exe" wide //weight: 1
        $x_1_5 = "\\Program Files\\winnt\\winlogon.exe" wide //weight: 1
        $x_1_6 = "\\Documents and Settings\\All Users\\Documents\\My Music\\winsys.exe" wide //weight: 1
        $x_1_7 = "\\Documents and Settings\\All Users\\Application Data\\now.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_VB_ABM_2147637360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ABM"
        threat_id = "2147637360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cnhack.cn/ok/2c.txt" wide //weight: 1
        $x_1_2 = "cnhack.cn/ok/cs/sfcpc1/k1.txt" wide //weight: 1
        $x_1_3 = "uweruuyq.cn/dm1.htm?" wide //weight: 1
        $x_1_4 = "vip2.51.la/go.asp?we=A-Free-Service-for-Webmasters&svid=7&id=1789127" wide //weight: 1
        $x_1_5 = "<a href= http://www.qq.com/>111111111111111111</a>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ABN_2147637427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ABN"
        threat_id = "2147637427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 00 31 00 38 00 2e 00 38 00 33 00 2e 00 31 00 36 00 31 00 2e 00 [0-2] 34 00 34 00 3a 00 38 00 38 00 2f 00 73 00 6f 00 66 00 74 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {78 00 78 00 78 00 78 00 2e 00 43 00 4c 00 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "t45158615" wide //weight: 1
        $x_1_4 = "_fmm.r._0.a=&refuser=&appendinfo=&regcheck=regcheck&" wide //weight: 1
        $x_1_5 = "c:\\zc.bat&echo del" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ABO_2147637524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ABO"
        threat_id = "2147637524"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /f /im ZhuDongFangyu.exe" wide //weight: 1
        $x_1_2 = "shenjingyuanie520" wide //weight: 1
        $x_1_3 = "e6723vgmxkhij18ubyf59oltanrsd0wcpq4z" wide //weight: 1
        $x_1_4 = "{C42EB5A1-0EED-E549-91B0-153485866016}" wide //weight: 1
        $x_1_5 = {5c 00 7e 81 af 8b 54 00 54 00 2e 00 54 00 54}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ABP_2147637525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ABP"
        threat_id = "2147637525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2008-11-4 18:24:09" wide //weight: 1
        $x_1_2 = {64 00 39 00 00 00 1c 00 00 00 31 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 3f 00 31 00 32 00 33 00 34 00 35 00 36}  //weight: 1, accuracy: High
        $x_1_3 = {68 00 65 00 00 00 08 00 00 00 6e 00 62 00 75 00 63 00 00 00 00 00 16 00 00 00 75 00 6f 00 2e 00 63 00 6f 00 6d 00 2f 00 3f 00 31 00 32 00 33 00 00 00 06 00 00 00 34 00 35 00 36}  //weight: 1, accuracy: High
        $x_1_4 = {47 00 3a 00 5c 00 11 62 84 76 56 00 42 00 5c 00 a9 8b 7e 76 a6 5e 1c 64 22 7d d3 7e 9c 67 bb 53 07 63 9a 5b 30 57 40 57 5c 00 75 00 39 00 75 00 38 00 0b 4e 7d 8f 4b 6d d5 8b 5c 00 85 8f 32 00 f7 53 b0 65 20 00 43 00 46 00 5c 00 74 00 65 00 6e 00 6e 00 65 00 6e 00 74 00 2e 00 76 00 62 00 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ABQ_2147637609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ABQ"
        threat_id = "2147637609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "niuchen2016@yahoo.cn" ascii //weight: 1
        $x_1_2 = "908387247@qq.com" ascii //weight: 1
        $x_1_3 = "//58.webqv.com/881/ps.txt" wide //weight: 1
        $x_1_4 = "//gzhtcmsau.blog.163.com/vote/3414016/" wide //weight: 1
        $x_1_5 = {51 00 51 00 3a 00 00 00 0e 00 00 00 52 00 30 00 52 00 2e 00 74 00 78 00 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ABR_2147637627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ABR"
        threat_id = "2147637627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "qv-qq.com/GetUID.asp" wide //weight: 1
        $x_1_2 = "gzhtcmsau.blog.163.com/vote/3414016/" wide //weight: 1
        $x_1_3 = "AliIM.exe/beta/qq.exe>abcd" wide //weight: 1
        $x_1_4 = {2a 00 5c 00 41 00 45 00 3a 00 5c 00 36 00 33 00 39 00 39 00 5c 00 [0-90] 5c 00 4d 00 53 00 47 00 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_5 = {51 00 51 00 3a 00 00 00 0e 00 00 00 52 00 30 00 52 00 2e 00 74 00 78 00 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ABS_2147637666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ABS"
        threat_id = "2147637666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /f /im ZhuDongFangyu.exe" wide //weight: 1
        $x_1_2 = "shenjingyuanie520" wide //weight: 1
        $x_1_3 = "xujia.reg" wide //weight: 1
        $x_1_4 = "\\Mozilla Firefox.huo" wide //weight: 1
        $x_1_5 = {5c 00 7e 81 af 8b 54 00 54 00 2e 00 54 00 54}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ABT_2147637673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ABT"
        threat_id = "2147637673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "shenjingyuanie520" wide //weight: 1
        $x_1_2 = {5c 00 73 00 74 00 6f 00 70 00 ?? ?? ?? ?? ?? ?? 5c 00 6d 00 73 00 64 00 63 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 00 2a 00 2a 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5f 00 53 00 65 00 72 00 76 00 65 00 72 00 [0-218] 31 00 2a 00 2a 00 58 00 54 00 50 00 54 00 61 00 73 00 6b 00 50 00 61 00 6e 00 65 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ABU_2147637972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ABU"
        threat_id = "2147637972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "del   kill.bat" wide //weight: 1
        $x_1_2 = "XIFAJLFAFJA" wide //weight: 1
        $x_1_3 = "763bhsdfhgdhdbwtrwbtrwbtrwbbd57" wide //weight: 1
        $x_1_4 = "fdafs57654vsgfsbhgbwrtbtrwbtrdnhgnddfa" wide //weight: 1
        $x_1_5 = "8746457654ugejrwtbrwebtrwbtrgdfjgdfjgfdhgfdhgd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ABV_2147638385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ABV"
        threat_id = "2147638385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Loader_jieku_977.exe" wide //weight: 1
        $x_1_2 = "haozip_tiny.200629[1].htm" wide //weight: 1
        $x_1_3 = {61 00 6e 00 6b 00 74 00 79 00 2e 00 73 00 61 00 6e 00 ?? ?? ?? ?? ?? ?? ?? ?? 64 00 75 00 7a 00 75 00 6f 00 2e 00 63 00 6e 00 3a 00 32 00 39 00 30 00 33 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 00 0b 4e 7d 8f 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 00 4e 74 65 57 59 d2 63 f6 4e 5c 00 0b 4e 7d 8f 89 5b c5 88 ba 4e b6 5b d2 63 f6 4e 5c 00 e5 5d 0b 7a 31 00 2e 00 76 00 62 00 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ABW_2147638427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ABW"
        threat_id = "2147638427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 00 20 00 69 00 74 00 44 00 4c 00 4c 00 60 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 00 61 00 6c 00 64 00 39 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 75 00 2d 00 65 00 6e 00 47 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {73 00 68 00 65 00 6e 00 6a 00 69 00 6e 00 67 00 79 00 75 00 61 00 6e 00 69 00 65 00 35 00 32 00 30 00 54 00 4c 00 6f 00 63 00 61 00 74 00 69 00 6f 00 6e 00 55 00 52 00 4c 00 00 00 4e 00 61 00 76 00 69 00 67 00 61 00 74 00 65 00 32 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b ff 2b 00 32 00 43 00 49 00 63 00 6f 00 73 00 2a 00 ?? ?? b0 ff 64 00 61 00 64 00 6a 00 5f 00 66 00 70 00 74 00 61 00 6e 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? e0 ff 64 00 69 00 76 00 5f 00 6d 00 36 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 60 00 30 00 6d 00 31 00 69 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ABX_2147638436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ABX"
        threat_id = "2147638436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%2E%61%64%6D%61%6D%61%2E%63%6E/count.aspx" wide //weight: 1
        $x_1_2 = {53 00 65 00 6e 00 64 00 43 00 6f 00 75 00 6e 00 74 00 31 00 31 00 2e 00 65 00 78 00 65 00 22 00 4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {09 4e db 6b 36 52 5c 4f 20 00 51 00 51 00 3a 00 35 00 31 00 30 00 37 00 38 00 34 00 35 00 31 00 38 00 1a 00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ABY_2147638499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ABY"
        threat_id = "2147638499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "ddddsswwer" wide //weight: 3
        $x_1_2 = ".73s.net/ht/index.htm" wide //weight: 1
        $x_1_3 = ".erqj.com/ht/index.htm" wide //weight: 1
        $x_1_4 = {2e 00 35 00 36 00 39 00 39 00 35 00 2e 00 63 00 6f 00 6d 00 2f 00 68 00 74 00 2f 00 69 00 6e 00 64 00 65 00 78 00 ?? ?? 2e 00 68 00 74 00 6d 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 00 70 00 65 00 74 00 69 00 74 00 62 00 6f 00 79 00 2e 00 6e 00 65 00 74 00 2f 00 68 00 74 00 2f 00 69 00 6e 00 64 00 65 00 78 00 ?? ?? 2e 00 68 00 74 00 6d 00 6c 00}  //weight: 1, accuracy: Low
        $x_3_6 = {66 64 66 66 73 67 66 31 00 00 00 00 66 66 67 66 67 66 67 66 32 00 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_ABZ_2147638500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ABZ"
        threat_id = "2147638500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".73s.net/ht/index.htm" wide //weight: 1
        $x_1_2 = {2e 00 70 00 61 00 69 00 6e 00 77 00 65 00 62 00 2e 00 6e 00 65 00 74 00 2f 00 68 00 74 00 2f 00 69 00 6e 00 64 00 65 00 78 00 ?? ?? 2e 00 68 00 74 00 6d 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {66 66 67 66 67 66 67 66 32 00 00 00 66 64 66 66 73 67 66 31 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ACA_2147638541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ACA"
        threat_id = "2147638541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".gomowieop.com/29.txt" wide //weight: 1
        $x_1_2 = "gotoshfdop.com/29.doc" wide //weight: 1
        $x_1_3 = ".gombaihop.com/29.php" wide //weight: 1
        $x_1_4 = ".34800.com/pop/" wide //weight: 1
        $x_1_5 = ".3sgou.com/pop/" wide //weight: 1
        $x_1_6 = {32 00 35 00 33 00 31 00 33 00 33 00 33 00 66 00 64 00 64 00 64 00 64 00 67 00 64 00 64 00 ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 35 00 36 00 39 00 39 00 35 00 2e 00 63 00 6f 00 6d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ACB_2147638544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ACB"
        threat_id = "2147638544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".bdskw.cn" wide //weight: 1
        $x_1_2 = ".56995.com" wide //weight: 1
        $x_1_3 = {2f 00 68 00 74 00 2f 00 6d 00 61 00 6d 00 61 00 2e 00 74 00 78 00 74 00 ?? ?? ?? ?? ?? ?? ?? ?? 2f 00 68 00 74 00 2f 00 74 00 69 00 61 00 6f 00 31 00 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_4 = "%B6%AB%B7%BD%C9%F1%C6%F0%D7%EE%D0%C2%CD%BC&oq=dfs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ACC_2147638545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ACC"
        threat_id = "2147638545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AllInIETenQQcent123ByLiZhao" ascii //weight: 1
        $x_1_2 = "{C42EB5A1-0EED-E549-91B0-" wide //weight: 1
        $x_1_3 = "BFHMKGKHJGIMONLJGGBNGECIAKHOICFEGGOIDCIAJKMO@EO@C" wide //weight: 1
        $x_1_4 = {63 00 6f 00 75 00 6e 00 74 00 2f 00 69 00 70 00 2e 00 61 00 73 00 70 00 3f 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 26 00 6d 00 61 00 63 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 00 6c 00 69 00 61 00 6e 00 6d 00 65 00 6e 00 67 00 3d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ACD_2147638596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ACD"
        threat_id = "2147638596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "{C42EB5A1-0EED-E549-91B0-153485860019}" wide //weight: 1
        $x_1_2 = "e6723vgmxkhij18ubyf59oltanrsd0wcpq4z" wide //weight: 1
        $x_1_3 = {73 00 68 00 6f 00 75 00 73 00 68 00 6f 00 75 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 20 00 5a 00 68 00 75 00 44 00 6f 00 6e 00 67 00 46 00 61 00 6e 00 67 00 79 00 75 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ACE_2147638616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ACE"
        threat_id = "2147638616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "shenjingyuanie520" wide //weight: 1
        $x_1_2 = {53 00 74 00 61 00 74 00 2e 00 61 00 73 00 68 00 78 00 3f 00 4d 00 61 00 63 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? 26 00 48 00 61 00 72 00 64 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? 26 00 43 00 6c 00 69 00 65 00 6e 00 74 00 54 00 79 00 70 00 65 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? 26 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 3d 00 ?? ?? ?? ?? ?? ?? 26 00 55 00 73 00 65 00 72 00 49 00 44 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? 26 00 41 00 75 00 74 00 68 00 65 00 6e 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_3 = "HAH@KGOI@OEM@FIKDBIJFICFLAOHMKHLIM@FBJLEGGALHDGGGGFJ@OHMOHPBDOJGCEMOKDGBMALADBJGL@NKDCPB@EGDIIKGBI@" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ACF_2147638714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ACF"
        threat_id = "2147638714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shenjingyuanie520" wide //weight: 1
        $x_1_2 = "{C42EB5A1-0EED-E549-91B0-153485860006}" wide //weight: 1
        $x_1_3 = "e6723vgmxkhij18ubyf59oltanrsd0wcpq4z" wide //weight: 1
        $x_1_4 = "taskkill /f /im ZhuDongFangyu.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ACG_2147638843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ACG"
        threat_id = "2147638843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sfdgsdfsdffsdff" wide //weight: 1
        $x_1_2 = "HAH@KGOI@OEM@FIKDBIJFICFLAOHMKHLIM@FBJLE" wide //weight: 1
        $x_1_3 = {64 00 72 00 76 00 2e 00 74 00 78 00 74 00 61 00 30 00 43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 77 00 64 00 6d 00 61 00 75 00 64 00 2e 00 64 00 72 00 76 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ACH_2147638866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ACH"
        threat_id = "2147638866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sfdgsdfsdffsdff" wide //weight: 1
        $x_1_2 = "l6phryf02tdimanx4b7g5e3wjz8uvs9oc1qk" wide //weight: 1
        $x_1_3 = "HAH@KGOI@OEM@FIKDBIJFICFLAOHMKHLIM@FBJLEALALHDHMIMFJHMGFPB@NE@" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ADF_2147640941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ADF"
        threat_id = "2147640941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Arquivos de programas\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 1
        $x_1_2 = "WH#EN%UCOM&EBACKI*WI(LLF@ICKY!OU" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ADM_2147641193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ADM"
        threat_id = "2147641193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "AliIM.exe/beta/qq.exe" wide //weight: 4
        $x_1_2 = "ESET Nod32" wide //weight: 1
        $x_1_3 = "KPfwSvc" wide //weight: 1
        $x_1_4 = "360Tray.exe" wide //weight: 1
        $x_2_5 = "txt.asp?host=" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ADR_2147641833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ADR"
        threat_id = "2147641833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 01 6a ff 6a 02 ff 15 ?? ?? ?? ?? 8d 4d ?? ff 15 ?? ?? ?? ?? c7 45 fc ?? 00 00 00 c7 85 ?? fe ff ff ?? ?? ?? ?? c7 85 ?? fe ff ff 08 00 00 00 c7 85 ?? fe ff ff ?? ?? ?? ?? c7 85 ?? fe ff ff 08 00 00 00 8d 8d ?? fe ff ff 51 8b 55 08 83 c2 34 52}  //weight: 1, accuracy: Low
        $x_1_2 = "cmd /c taskkill /f /im" wide //weight: 1
        $x_1_3 = "CreateObject(\"WScript.Shell\").Run \"cmd /c" wide //weight: 1
        $x_1_4 = "g.cn/g.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_ADZ_2147642356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.ADZ"
        threat_id = "2147642356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "RadioStarUpdater.vbp" wide //weight: 10
        $x_10_2 = "78E1BDD1-9941-11cf-9756-00AA00C00908" wide //weight: 10
        $x_10_3 = "AutoRun" wide //weight: 10
        $x_1_4 = "run.php" wide //weight: 1
        $x_1_5 = {63 00 6f 00 6d 00 64 00 6f 00 70 00 6c 00 75 00 73 00 [0-4] 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
        $x_1_6 = {6b 00 63 00 63 00 6f 00 74 00 69 00 6f 00 6e 00 [0-4] 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
        $x_1_7 = {67 00 6d 00 48 00 54 00 54 00 50 00 5f 00 52 00 45 00 51 00 55 00 45 00 53 00 54 00 ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 74 00 6d 00 70 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 53 00 63 00 72 00 69 00 70 00 74 00 69 00 6e 00 67 00 2e 00 46 00 69 00 6c 00 65 00 53 00 79 00 73 00 74 00 65 00 6d 00 4f 00 62 00 6a 00 65 00 63 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_YAK_2147642538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.YAK"
        threat_id = "2147642538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "kaoti.exe" wide //weight: 1
        $x_1_2 = {61 00 68 00 75 00 69 00 2e 00 65 00 78 00 65 00 2c 00 20 00 30 00 28 00 43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_3 = "c.greenclick.cn/click?pid=23&mid=19483&channel=2&pt=df" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_YAB_2147642539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.YAB"
        threat_id = "2147642539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Hijack.exe" wide //weight: 1
        $x_1_2 = "nResurrection.bat" wide //weight: 1
        $x_1_3 = ".18286.net/?xin" wide //weight: 1
        $x_1_4 = "NaNianHuaKai" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_AEP_2147642925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.AEP"
        threat_id = "2147642925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ECTACO" wide //weight: 1
        $x_1_2 = "KeServiceDescriptorTable" wide //weight: 1
        $x_1_3 = "ExecQuery" wide //weight: 1
        $x_1_4 = "Nonauthoritative host not found" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_AEQ_2147642952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.AEQ"
        threat_id = "2147642952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Work\\test\\Summer.vbp" wide //weight: 1
        $x_1_2 = "YES.infected" wide //weight: 1
        $x_1_3 = "NtWriteVirtualMemory" wide //weight: 1
        $x_1_4 = "AppendChunk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_AER_2147642976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.AER"
        threat_id = "2147642976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ModGetIEObject" ascii //weight: 3
        $x_3_2 = "ModGetProcessNameByProcessId" ascii //weight: 3
        $x_2_3 = "SHELLHOOK" wide //weight: 2
        $x_2_4 = "Maxthon2_View" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_YAF_2147643078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.YAF"
        threat_id = "2147643078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\KB95674456.log" wide //weight: 1
        $x_1_2 = "tskill DNFchina" wide //weight: 1
        $x_1_3 = "/ryjwyj.vip.dns12580.com/kankan.txt" wide //weight: 1
        $x_1_4 = "|104_8|105_9|106_*|107_+|109_-|110_.|111_/|13_Enter|" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_AFX_2147644615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.AFX"
        threat_id = "2147644615"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "UDPFlood" ascii //weight: 10
        $x_10_2 = "SeriNoAl" ascii //weight: 10
        $x_10_3 = "haryvideo.exe" wide //weight: 10
        $x_1_4 = "Desktop\\ery\\ery.vbp" wide //weight: 1
        $x_1_5 = "Trend Micro Inc" wide //weight: 1
        $x_1_6 = "Hijack This" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_AGB_2147645626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.AGB"
        threat_id = "2147645626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 68 6b 07 00 00 6a 31 89 75 ?? 89 75}  //weight: 1, accuracy: Low
        $x_1_2 = {43 00 3a 00 5c 00 43 00 61 00 6e 00 64 00 79 00 5c 00 [0-37] 5c 00 50 00 72 00 6f 00 6a 00 65 00 6b 00 74 00 31 00 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_AGE_2147645775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.AGE"
        threat_id = "2147645775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 75 bb db fb f7 d8 b9 3e 37 f2 3c 83 d1 00 f7 d9 89 45 ?? 89 4d ?? 6a 00 6a 00 6a 00 ff 75 ?? 8d 45 ?? 50 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 08 ff 75 ?? 89 45 ?? c7 45 ?? 03 40 00 00 8d 5d ?? e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_AGF_2147645825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.AGF"
        threat_id = "2147645825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Microsoft\\Internet Explorer\\main" wide //weight: 10
        $x_10_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 10
        $x_2_3 = "ChromeFck\\obj" ascii //weight: 2
        $x_2_4 = "\\\\messenger.exe" wide //weight: 2
        $x_2_5 = "HomeBlocker.exe" wide //weight: 2
        $x_1_6 = "http://www.proarama.com" wide //weight: 1
        $x_1_7 = "http://www.plustvarama.com" wide //weight: 1
        $x_1_8 = "http://www.traramayeri.net" wide //weight: 1
        $x_1_9 = "http://www.fixarabul.com" wide //weight: 1
        $x_1_10 = "http://www.fixarasana.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VB_AGT_2147647084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.AGT"
        threat_id = "2147647084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "thisissvchost" ascii //weight: 3
        $x_2_2 = "cmd.exe /c copy /y \"" wide //weight: 2
        $x_1_3 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_AHC_2147648825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.AHC"
        threat_id = "2147648825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 43 6f 6f 6b 69 65 41 6e 64 43 61 63 68 65 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 6d 6f 64 45 6e 61 62 6c 65 50 72 69 76 69 6c 65 67 65 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 6d 4c 6f 63 61 6c 4d 41 43 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 6d 6f 64 48 6f 6f 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_AHQ_2147650644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.AHQ"
        threat_id = "2147650644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "errResult = objSWbemObject.Create(\"cmd.exe /c ipconfig /release\", Null, objConfig, processId)" wide //weight: 2
        $x_1_2 = "\\Hijack.exe" wide //weight: 1
        $x_3_3 = "ModGetProNameByProId" ascii //weight: 3
        $x_2_4 = "ReqTongji" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_AIR_2147658198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.AIR"
        threat_id = "2147658198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {79 09 66 4b 66 81 cb 00 ff 66 43 0f bf c3 8d 4d bc 50 51 ff 15 ?? 10 40 00 8d 95 7c ff ff ff 8d 45 bc 52 8d 4d ac 50 51 ff 15 ?? ?? 40 00 50 ff 15 ?? 10 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d e0 8b 55 ?? 51 52 ff d3 8b d0 8d 4d e0 ff d6 b8 02 00 00 00 03 c7 0f 80 86 00 00 00 8b f8 b8 02 00 00 00 e9 42 ff ff ff 8b 55 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_AIX_2147658936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.AIX"
        threat_id = "2147658936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Documents and Settings\\Administrator\\Application Data" wide //weight: 1
        $x_1_2 = "Fan Project\\FanProject.vbp" wide //weight: 1
        $x_1_3 = "\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "VBRUN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VB_YDH_2147720063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB.YDH!bit"
        threat_id = "2147720063"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "360sd.exe,360" wide //weight: 1
        $x_1_2 = "<Command>infdefaultinstall</Command>" wide //weight: 1
        $x_1_3 = "cmd /c netsh firewall set opmode mode=DISABLE exceptions=ENABLE" wide //weight: 1
        $x_1_4 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\tmall.com\\*" wide //weight: 1
        $x_1_5 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\taobao.com\\*" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_VB_13710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VB"
        threat_id = "13710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EncriptaAPI" ascii //weight: 1
        $x_1_2 = "Stubdos" ascii //weight: 1
        $x_1_3 = "C:\\WINDOWS\\system32\\weweweee.dll" ascii //weight: 1
        $x_1_4 = "vbasssssrCopy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

