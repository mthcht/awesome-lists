rule TrojanSpy_Win32_Agent_2147800051_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent"
        threat_id = "2147800051"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "WINDOWS\\system32\\scvhost.exe" ascii //weight: 1
        $x_1_3 = "virtual-net.pisem.su/Nick.gif" ascii //weight: 1
        $x_1_4 = "InternetReadFile" ascii //weight: 1
        $x_1_5 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_6 = "InternetOpenA" ascii //weight: 1
        $x_1_7 = "InternetCloseHandle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Agent_2147800051_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent"
        threat_id = "2147800051"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "f:\\source\\cg\\cgall\\wmgj\\wmgjexe" ascii //weight: 1
        $x_1_2 = "cmd=1&usrname=%s&usrpass=%s&servername=%s&bankpass=%s&nickname=%s&rankinfo=%d" ascii //weight: 1
        $x_1_3 = "ACTION_OFFLINE_CLIENT" ascii //weight: 1
        $x_1_4 = "ReadProcessMemory with PINCODE-value fault, code = %d" ascii //weight: 1
        $x_1_5 = "szAccount = %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanSpy_Win32_Agent_2147800051_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent"
        threat_id = "2147800051"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bonus 1.exe" wide //weight: 1
        $x_1_2 = "http://wmr-moneys.org/config/line.gif" wide //weight: 1
        $x_1_3 = "http://countexchange.com/config/line.gif" wide //weight: 1
        $x_1_4 = "?a=wmk:payto?Purse=" wide //weight: 1
        $x_1_5 = "&Amount=" wide //weight: 1
        $x_1_6 = "&Desc=" wide //weight: 1
        $x_1_7 = "\\Bonus 1.5.vbp" wide //weight: 1
        $x_1_8 = "\\SOFT2" wide //weight: 1
        $x_1_9 = "*\\AG:\\Vladimir\\Desktop\\" wide //weight: 1
        $x_1_10 = "WebMoney" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Agent_2147800051_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent"
        threat_id = "2147800051"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {e8 00 00 00 00 5f 33 f7 b8 a1 9f 40 00 8b c8 51 83 c0 32 c3 bb 00 10 40 00 81 eb 28 71 ff ff 53 75 05 33 c0 74 01 e9 fc b8 4b 9f}  //weight: 10, accuracy: High
        $x_1_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 7e 54 65 6d 70 [0-4] 2e 74 6d 70 00 00 00 00 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = "c:\\home\\mwtest\\tmp\\w.exe" ascii //weight: 1
        $x_1_4 = "c:\\windows\\system32\\1.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Agent_IA_2147801612_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.IA"
        threat_id = "2147801612"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\ADWARA\\prjX.vbp" wide //weight: 10
        $x_10_2 = "Windows (tm), Security Provider(tm), msbind (tm)" wide //weight: 10
        $x_3_3 = "F146C9B1-VMVQ-A9RC-NUFL-D0BA00B4E999" wide //weight: 3
        $x_3_4 = "Y479C6D0-OTRW-U5GH-S1EE-E0AC10B4E666" wide //weight: 3
        $x_2_5 = "ShellExecuteA" ascii //weight: 2
        $x_2_6 = "Process32First" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Agent_A_2147801921_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.A"
        threat_id = "2147801921"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "\\getpasses.exe" wide //weight: 10
        $x_10_3 = "-Messengerpasses.txt" wide //weight: 10
        $x_10_4 = "\\Administrator\\Desktop\\Steal0r's\\Messenger Steal0r" wide //weight: 10
        $x_1_5 = "frm_Main" ascii //weight: 1
        $x_1_6 = "\\passes.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Agent_DA_2147803118_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.DA"
        threat_id = "2147803118"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "441"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Antohinsait" ascii //weight: 100
        $x_100_2 = "Software\\Happy" ascii //weight: 100
        $x_100_3 = "http://anty.freehostia.com/xxx/" ascii //weight: 100
        $x_100_4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 100
        $x_10_5 = "ExitWindowsEx" ascii //weight: 10
        $x_10_6 = "InternetReadFile" ascii //weight: 10
        $x_10_7 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_8 = "SeShutdownPrivilege" ascii //weight: 10
        $x_1_9 = "?nick=" ascii //weight: 1
        $x_1_10 = "&info=iBank2" ascii //weight: 1
        $x_1_11 = "logo.png" ascii //weight: 1
        $x_1_12 = "ftp.narod.ru" ascii //weight: 1
        $x_1_13 = "Sorry, service is currently not available" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Agent_FL_2147803460_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.FL"
        threat_id = "2147803460"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "-42ae-99AA-ADC21CCBBE14}" ascii //weight: 1
        $x_1_2 = "http://onlinesearch4meds.com" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "localhost" ascii //weight: 1
        $x_1_5 = "EHLO " ascii //weight: 1
        $x_1_6 = "AUTH LOGIN" ascii //weight: 1
        $x_1_7 = "MAIL FROM:<" ascii //weight: 1
        $x_1_8 = "RCPT TO:<" ascii //weight: 1
        $x_1_9 = "DnsQuery_A" ascii //weight: 1
        $x_1_10 = "DnsRecordListFree" ascii //weight: 1
        $x_1_11 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_12 = "CreateMutexW" ascii //weight: 1
        $x_1_13 = "GetComputerNameExA" ascii //weight: 1
        $x_20_14 = "Global\\{2C6E70A2-FB03-4366-912C-CA53CCCA3B60}" wide //weight: 20
        $x_20_15 = {56 33 f6 83 7c 24 0c 01 75 ?? 68 ?? ?? 00 10 6a 01 56 ff 15 60 c0 00 10 3b c6 a3 48 e0 00 10 74 ?? ff 15 78 c0 00 10 3d b7 00 00 00 74}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 12 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Agent_CQ_2147803654_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.CQ"
        threat_id = "2147803654"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 80 fc 02 00 00 22 c8 00 00 e8 ?? ?? ?? ?? b2 01 a1 58 ad 46 00 e8 ?? ?? ?? ?? 8b 55 fc 89 82 f8 02 00 00}  //weight: 5, accuracy: Low
        $x_2_2 = {05 fc 02 00 00 b9 04 00 00 00 8b d3 e8 ?? ?? ?? ?? 83 c3 04 8d 45 f8 b9 04 00 00 00 8b d3 e8 ?? ?? ?? ?? 83 c3 04 8b 45 fc 05 00 03 00 00 8b 55 f8}  //weight: 2, accuracy: Low
        $x_1_3 = "Screen Capture" ascii //weight: 1
        $x_1_4 = "Cammy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Agent_GP_2147803795_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.GP"
        threat_id = "2147803795"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 73 79 73 74 68 65 63 61 74 6d 73 67 2e 67 69 66 00 00 00 47 49 46 00 45 58 45 00 49 4e 46 00 25 73 0a 00 77 00 00 00 5c 73 79 73 6d 73 67 70 72 6f 63 65 73 73}  //weight: 1, accuracy: High
        $x_1_2 = {46 69 72 73 74 4e 61 6d 65 00 00 00 78 69 6e 67 00 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 34 35 35 34 36 35 78 2e 63 6f 6d 2f 74 65 73 74 2f 49 50 2e 61 73 70}  //weight: 1, accuracy: High
        $x_1_3 = {26 50 61 73 73 77 6f 72 64 3d 00 00 3f 4e 75 6d 62 65 72 3d 00 00 00 00 51}  //weight: 1, accuracy: High
        $x_1_4 = {54 65 6e 63 65 6e 74 5f 51 51 42 61 72 00 00 00 73 79 73 6d 73 67 74 61 72 74 00 00 53 4f 46 54}  //weight: 1, accuracy: High
        $x_1_5 = {51 51 2e 65 78 65 00 00 5c 74 68 65 6d 73 67 6d 6f 76 65 2e 65 78 65 00 5c 61 75 74 6f 72 75 6e 2e 69 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Agent_JA_2147803825_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.JA"
        threat_id = "2147803825"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|Options.InfectFiles=" ascii //weight: 1
        $x_1_2 = "KeyLogger.Active" ascii //weight: 1
        $x_1_3 = "|Options.DeactiveKasperSky=" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Agent_BP_2147803867_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.BP"
        threat_id = "2147803867"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_2 = "GetClipboardData" ascii //weight: 10
        $x_10_3 = "GetOpenFileNameA" ascii //weight: 10
        $x_10_4 = "FtpPutFileA" ascii //weight: 10
        $x_1_5 = "http://kokovs.cc/porno/stat.php" ascii //weight: 1
        $x_1_6 = "?nick=" ascii //weight: 1
        $x_1_7 = "&info=iBank2" ascii //weight: 1
        $x_1_8 = "Software\\JavaSoft\\Prefs" ascii //weight: 1
        $x_1_9 = "logo.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Agent_PI_2147803870_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.PI"
        threat_id = "2147803870"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Install Service Success,Ready Execute Work Thread..." ascii //weight: 1
        $x_1_2 = "No Find Service,Ready Install Service..." ascii //weight: 1
        $x_1_3 = "No Find RedGirl Server,Installing..." ascii //weight: 1
        $x_1_4 = "htmlfile\\shell\\open\\command" ascii //weight: 1
        $x_1_5 = "if exist \"%s\" goto delete" ascii //weight: 1
        $x_1_6 = "!*_*->seven-eleven<-*_*!" ascii //weight: 1
        $x_1_7 = "%s Inject To Browser..." ascii //weight: 1
        $x_1_8 = "\\tmp.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Agent_GR_2147803877_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.GR"
        threat_id = "2147803877"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ShellExecuteExA" ascii //weight: 1
        $x_1_2 = "wordpad.exe" ascii //weight: 1
        $x_1_3 = "User: %s" ascii //weight: 1
        $x_1_4 = "STOR %s" ascii //weight: 1
        $x_1_5 = "PASS %s" ascii //weight: 1
        $x_1_6 = "IEUser@" ascii //weight: 1
        $x_1_7 = {20 3e 20 6e 75 6c 00 00 2f 63 20 64 65 6c 20}  //weight: 1, accuracy: High
        $x_1_8 = "ftp://" ascii //weight: 1
        $x_1_9 = "Hardware\\Description\\System\\CentralProcessor\\0" ascii //weight: 1
        $x_1_10 = {68 74 74 70 3a 2f 2f 00 63 6f 6e 74 65 6e 74 2d 6c 65 6e 67 74 68}  //weight: 1, accuracy: High
        $x_10_11 = {74 28 6a 02 53 53 55 ff 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 56 6a 1e 8d 44 24 1c 50 bd ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5b 3c 5d 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Agent_PO_2147803878_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.PO"
        threat_id = "2147803878"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SYSTEM\\CurrentControlSet\\Services\\" ascii //weight: 1
        $x_1_2 = "RegisterServiceCtrlHandlerA" ascii //weight: 1
        $x_1_3 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_4 = "CreateRemoteThread" ascii //weight: 1
        $x_1_5 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_6 = "ShellExecuteA" ascii //weight: 1
        $x_1_7 = "360Tray.exe" ascii //weight: 1
        $x_1_8 = "360Safe.exe" ascii //weight: 1
        $x_1_9 = "if exist \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Agent_FGI_2147803913_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.FGI"
        threat_id = "2147803913"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 56 56 68 cc 00 00 00 ff 35 f4 63 40 00 bd e8 67 40 00 bb 44 63 40 00 6a 1a 6a 1c 6a 22 6a 04 68 00 00 00 50 55 53 56 ff d7 a3 20 64 40 00}  //weight: 5, accuracy: High
        $x_1_2 = {68 00 00 88 00 68 68 63 40 00 68 60 63 40 00 56 ff d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Agent_FGH_2147803914_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.FGH"
        threat_id = "2147803914"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&tytul=Tibissa.com&tresc=Nazwa%20konta:" ascii //weight: 1
        $x_1_2 = "DockSite" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii //weight: 1
        $x_1_4 = ".gif%3E <br> ........ " ascii //weight: 1
        $x_1_5 = "\\ocsdebug.txt" ascii //weight: 1
        $x_1_6 = "Tibia - Free Multiplayer Online Role Playing Game - Account" ascii //weight: 1
        $x_1_7 = ">Character%20on%20the%20map<a>&od=" ascii //weight: 1
        $x_1_8 = ">Zobacz%20postac%20na%20Tibia.com<a>+<br>+<a%20href=https://secure.tibia.com/account/?subtopic=accountmanagement>Zaloguj%20sie%20na%20Tibia.com<a>+<br>+<a%20href=http://tibia.pl/earth.php?x=" ascii //weight: 1
        $x_1_9 = "<br>Haslo:" ascii //weight: 1
        $x_1_10 = "<br>World:" ascii //weight: 1
        $x_1_11 = "&tytul=Tibissa.com&tresc=Account%20name:" ascii //weight: 1
        $x_1_12 = ">Polozenie%20postaci%20na%20mapie<a>&od=" ascii //weight: 1
        $x_1_13 = "<br><a%20href=http://www.tibia.com/community/?subtopic=characters%26name=" ascii //weight: 1
        $x_1_14 = ".gif%3E<br>Identyfikator:" ascii //weight: 1
        $x_1_15 = "vcltest3.dll" ascii //weight: 1
        $x_1_16 = "ListActns" ascii //weight: 1
        $x_1_17 = ">Informations%20from%20Tibia.com<a>+<br>+<a%20href=https://secure.tibia.com/account/?subtopic=accountmanagement>Login%20to%20Tibia.com<a>+<br>+<a%20href=http://tibia.pl/earth.php?x=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Agent_XFX_2147803916_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.XFX"
        threat_id = "2147803916"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "200"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "*\\AC:\\Documents and Settings\\tjasi\\Desktop\\Downloader\\Stub\\p.vbp" wide //weight: 10
        $x_100_2 = "URLDownloadToFile" wide //weight: 100
        $x_5_3 = "\\x.exe" wide //weight: 5
        $x_5_4 = "\\uninstall.exe" wide //weight: 5
        $x_10_5 = "http://whoisthis.100webspace.net/a.php?post=" wide //weight: 10
        $x_20_6 = "/stabular mm.txt" wide //weight: 20
        $x_20_7 = "/stabular ii.txt" wide //weight: 20
        $x_20_8 = "/stabular cc.txt" wide //weight: 20
        $x_20_9 = "\\signons3.txt" wide //weight: 20
        $x_2_10 = "thepiratebay" wide //weight: 2
        $x_2_11 = "paypal" wide //weight: 2
        $x_2_12 = "webmoney" wide //weight: 2
        $x_2_13 = "cpanel" wide //weight: 2
        $x_2_14 = "rapidshare" wide //weight: 2
        $x_2_15 = "megashare" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_20_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_100_*) and 4 of ($x_20_*) and 2 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_100_*) and 4 of ($x_20_*) and 1 of ($x_10_*) and 5 of ($x_2_*))) or
            ((1 of ($x_100_*) and 4 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_100_*) and 4 of ($x_20_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_100_*) and 4 of ($x_20_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Agent_GS_2147803917_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.GS"
        threat_id = "2147803917"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 6a 01 5f 68 e8 03 00 00 8d 85 90 fa ff ff 50 53 c7 45 bc 44 00 00 00 89 5d c0 89 5d c8 89 5d cc 89 5d d0 89 5d d4 89 5d d8 89 5d dc 89 5d e0 89 5d e4 89 7d e8 66 89 5d ee 89 5d f0 89 5d f4 89 5d f8 89 5d fc 66 c7 45 ec 05 00 89 5d c4 ff 15 ?? ?? ?? 00 6a 10 e8 ?? 42 00 00 59 8b f0 56 8d 45 bc 50 53 53 6a 20 57 53 53 53 8d 85 90 fa ff ff 50 ff 15 ?? ?? ?? 00 85 c0 74 0f ff 36 8b 3d ?? ?? ?? 00 ff d7 ff 76 04 ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 05 00 00 00 e9 10 00 00 00 68 90 80 40 00 b9 ?? 8c 40 00 e8 ?? ?? 00 00 c3 68 62 16 40 00 e8 ?? ?? 00 00 59 c3 b9 ?? 8c 40 00 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Agent_KA_2147803923_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.KA"
        threat_id = "2147803923"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "RCPT TO" ascii //weight: 1
        $x_1_3 = "MAIL FROM" ascii //weight: 1
        $x_1_4 = "webpop.xpg.com.br/Configuracoes.ini" ascii //weight: 1
        $x_1_5 = "netsh.exe" ascii //weight: 1
        $x_1_6 = "WSAAsyncGetHostByName" ascii //weight: 1
        $x_1_7 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Agent_TA_2147803939_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.TA"
        threat_id = "2147803939"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 32 35 30 00}  //weight: 10, accuracy: High
        $x_10_2 = {00 32 32 30 00}  //weight: 10, accuracy: High
        $x_10_3 = {00 71 75 69 74 0d 0a 00}  //weight: 10, accuracy: High
        $x_10_4 = {00 25 73 25 73 0d 0a 00}  //weight: 10, accuracy: High
        $x_10_5 = {00 25 61 2c 20 25 64 20 25 62 20 25 59 20 25 48 3a 25 4d 3a 25 53 20 00 00 25 64 30 30 00 00 00}  //weight: 10, accuracy: High
        $x_1_6 = {6a 00 68 03 00 1f 00 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 50 ff 15 ?? ?? ?? ?? (33|5f 5e 33) 8b e5 5d c2 0c 00 8d ?? ?? fe ff ff 68 04 01 00 00 50 6a 00 ff 15 ?? ?? ?? ?? 8d ?? ?? fe ff ff 51}  //weight: 1, accuracy: Low
        $x_1_7 = {01 00 00 53 56 57 6a 01 58 39 45 0c 0f 85 ?? ?? 00 00 33 db 68 ?? ?? ?? ?? 53 68 03 00 1f 00 ff 15 ?? ?? ?? ?? 3b c3 74 0c 50 ff 15 ?? ?? ?? ?? e9 ?? ?? 00 00 8d ?? ?? fe ff ff 68 04 01 00 00 50 53 ff 15 ?? ?? ?? ?? 8d ?? ?? fe ff ff 50 e8 ?? ?? ?? ?? be ?? ?? ?? ?? 8d 7d f0 a5 a5 a5 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Agent_CF_2147804024_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.CF"
        threat_id = "2147804024"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "build for Trojan.exe Version" ascii //weight: 1
        $x_1_2 = "<windir>\\avshld.exe" ascii //weight: 1
        $x_1_3 = "\\Software\\Internet Explorer\\" ascii //weight: 1
        $x_1_4 = "<windir>\\nvp.exe" ascii //weight: 1
        $x_1_5 = "<windir>\\avupdt.exe" ascii //weight: 1
        $x_1_6 = "\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\" ascii //weight: 1
        $x_1_7 = "berwacht den Systemstart" ascii //weight: 1
        $x_1_8 = {5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 5c 00 00 00 22 00 22 20 65 78 65 63 75 74 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_Win32_Agent_TB_2147804099_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.TB"
        threat_id = "2147804099"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 7d f0 a5 a0 ?? ?? 00 10 a5 a5 ?? ?? a4 80 45 f1 ?? 80 45 f2 ?? 80 45 f3 ?? 80 45 ?? ?? 80 45 ?? ?? 80 45}  //weight: 1, accuracy: Low
        $x_1_2 = {32 35 30 00 65 ?? ?? 00 25 73 3c 25 73 3e}  //weight: 1, accuracy: Low
        $x_1_3 = {32 35 30 00 65 32 38 00 71 75 69 74}  //weight: 1, accuracy: High
        $x_1_4 = "DnsQuery_A" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Agent_GQ_2147804154_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.GQ"
        threat_id = "2147804154"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "153"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "200.206.97.42" ascii //weight: 10
        $x_10_2 = "ACTIVX.exe" ascii //weight: 10
        $x_10_3 = "http://upload.exe" ascii //weight: 10
        $x_10_4 = "\\msjava32\\%s.key" ascii //weight: 10
        $x_10_5 = "C:\\windows\\xxxzzzyyy.exe" ascii //weight: 10
        $x_1_6 = "CallNextHookEx" ascii //weight: 1
        $x_1_7 = "InternetReadFile" ascii //weight: 1
        $x_1_8 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_100_9 = {8b 4d 08 8b 55 0c 8a 01 32 02 8b 4d 08 88 01 8b 55 0c 83 c2 01 89 55 0c 8b 45 08 83 c0 01 89 45 08}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Agent_DF_2147804196_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Agent.DF"
        threat_id = "2147804196"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "taskmgre.exe" ascii //weight: 2
        $x_1_2 = "taskkill /im " ascii //weight: 1
        $x_6_3 = "yvxccccccccczzzzzzzzzzccccc" ascii //weight: 6
        $x_1_4 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:8.0.1) Gecko/20100101 Firefox/8.0.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

