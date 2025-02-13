rule Trojan_Win32_Downloader_G_2147742245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.G!MTB"
        threat_id = "2147742245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\BeamWinHTTP2\\Release\\BeamWinHTTP.pdb" ascii //weight: 1
        $x_1_2 = "Accept-Language: ru-RU,ru" ascii //weight: 1
        $x_1_3 = "/c taskkill /im" ascii //weight: 1
        $x_1_4 = "/c start /I" ascii //weight: 1
        $x_1_5 = "country_code" ascii //weight: 1
        $x_1_6 = "iplogger.org" ascii //weight: 1
        $x_1_7 = "/success" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_AU_2147744736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.AU!MTB"
        threat_id = "2147744736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Mined" ascii //weight: 10
        $x_1_2 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "REGWRITE ( \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" ascii //weight: 1
        $x_1_4 = "David-PC" ascii //weight: 1
        $x_1_5 = "luser-PC" ascii //weight: 1
        $x_1_6 = "= \"WIN_XP\" THEN" ascii //weight: 1
        $x_1_7 = "$SERVER =" ascii //weight: 1
        $x_1_8 = "$USERNAME =" ascii //weight: 1
        $x_1_9 = "$PASS = " ascii //weight: 1
        $x_1_10 = "$PASSWORD = " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Downloader_GA_2147744863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.GA!MTB"
        threat_id = "2147744863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\BeamWinHTTP2\\Release\\BeamWinHTTP.pdb" ascii //weight: 10
        $x_10_2 = "\\BeamWinHTTP\\Release\\BeamWinHTTP.pdb" ascii //weight: 10
        $x_1_3 = "Accept-Language: ru-RU,ru" ascii //weight: 1
        $x_1_4 = "/c taskkill /im" ascii //weight: 1
        $x_1_5 = "/c start /I" ascii //weight: 1
        $x_1_6 = "iplogger.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Downloader_AT_2147745131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.AT!MTB"
        threat_id = "2147745131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "DIRREMOVE ( \"C:\\ProgramData\\SmartScreen\" , 1 )" ascii //weight: 10
        $x_1_2 = "Process Explorer" ascii //weight: 1
        $x_1_3 = "Process Hacker" ascii //weight: 1
        $x_1_4 = "PROCESSCLOSE ( WINGETPROCESS" ascii //weight: 1
        $x_1_5 = "procexp.exe" ascii //weight: 1
        $x_1_6 = "ProcessHacker.exe" ascii //weight: 1
        $x_1_7 = "REGWRITE ( \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"" ascii //weight: 1
        $x_1_8 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2f 00 [0-15] 2f 00 [0-15] 2f 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 6a 00 73 00 6f 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_9 = {68 74 74 70 3a 2f 2f [0-6] 2e [0-6] 2e [0-6] 2e [0-6] 2f [0-15] 2f [0-15] 2f 63 6f 6e 66 69 67 2e 6a 73 6f 6e}  //weight: 1, accuracy: Low
        $x_1_10 = {49 00 4e 00 45 00 54 00 47 00 45 00 54 00 20 00 28 00 20 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2f 00 [0-15] 2f 00 [0-15] 2f 00 [0-15] 2e 00 65 00 78 00 65 00 22 00}  //weight: 1, accuracy: Low
        $x_1_11 = {49 4e 45 54 47 45 54 20 28 20 22 68 74 74 70 3a 2f 2f [0-6] 2e [0-6] 2e [0-6] 2e [0-6] 2f [0-15] 2f [0-15] 2f [0-15] 2e 65 78 65 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Downloader_CS_2147750049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.CS!eml"
        threat_id = "2147750049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {30 30 31 2e 65 78 65 18 00 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c}  //weight: 2, accuracy: Low
        $x_1_2 = "\\wc.dat" ascii //weight: 1
        $x_2_3 = "\\fxgame.exe" ascii //weight: 2
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_2_5 = {31 31 30 33 2f 20 00 68 74 74 70 3a 2f 2f [0-15] 2f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Downloader_AUP_2147793784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.AUP!MTB"
        threat_id = "2147793784"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bf 2e c9 8c 00 41 81 e9 01 00 00 00 21 c9 e8 ?? ?? ?? ?? 68 82 02 39 5e 8b 04 24 83 c4 04 29 c1 81 e8 b9 83 17 26 31 3a 81 e8 9c 58 2b ad 01 c0 b9 52 df 29 7c 42 b8 e4 fa d0 5c 09 c8 39 f2 75 bf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_AC_2147797998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.AC!MTB"
        threat_id = "2147797998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VjrtublAlWoc" ascii //weight: 1
        $x_1_2 = "Get>oduWeHamdle" ascii //weight: 1
        $x_1_3 = "aswChLic.exe" ascii //weight: 1
        $x_1_4 = "@reaOeFi/eA" ascii //weight: 1
        $x_1_5 = "tFi/ePo*nte" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_AE_2147797999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.AE!MTB"
        threat_id = "2147797999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 51 9b 2c 4d 2b f0 8b 18 33 d1 33 da 81 c1 dc 95 1d 00 89 18 83 c0 04 8d 1c 06 3b df 76 e8}  //weight: 1, accuracy: High
        $x_1_2 = {8a c8 80 c1 41 88 4c 04 16 40 83 f8 1a 72 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_ADE_2147798214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.ADE!MTB"
        threat_id = "2147798214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 85 98 fe ff ff 83 f0 14 c7 85 9c fe ff ff 01 00 00 00 8b 8d 9c fe ff ff 89 85 78 fe ff ff 83 f1 00 89 8d 7c fe ff ff c7 85 88 fe ff ff 14 00 00 00 c7 85 8c fe ff ff 00 00 00 00 c7 85 90 fe ff ff d9 0d 01 00 c7 85 94 fe ff ff 00 00 00 00 c7 85 80 fe ff ff 52 67 00 00 c7 85 84 fe ff ff 00 00 00 00 8b 95 90 fe ff ff 8b bd 94 fe ff ff 8b 85 88 fe ff ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_ADT_2147798215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.ADT!MTB"
        threat_id = "2147798215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 6b 04 89 6c 24 04 8b ec 81 ec 1c 01 00 00 a1 14 e0 42 00 33 c5 89 45 fc 56 33 c0}  //weight: 10, accuracy: High
        $x_10_2 = {8b 06 89 45 fc 85 c0 74 0b 8b c8 ff 15 2c 71 42 00 ff 55 fc 83 c6 04 47 3b fb 75 e4}  //weight: 10, accuracy: High
        $x_1_3 = "Tenso.exe" ascii //weight: 1
        $x_1_4 = "192.95.10.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_RPG_2147798448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.RPG!MTB"
        threat_id = "2147798448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 3f 07 0b c7 45 84 00 00 00 00 c7 45 fc ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "VMware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_RPG_2147798448_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.RPG!MTB"
        threat_id = "2147798448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PowerShell" ascii //weight: 1
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "IHNhbCBhIE5ldy1PY" wide //weight: 1
        $x_1_4 = "-whatt" wide //weight: 1
        $x_1_5 = "-extdummt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_RPH_2147798449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.RPH!MTB"
        threat_id = "2147798449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdn.discordapp.com" wide //weight: 1
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "vbs.exe" wide //weight: 1
        $x_1_4 = "RunPE.RunPE" wide //weight: 1
        $x_1_5 = "RunPE.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_RPH_2147798449_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.RPH!MTB"
        threat_id = "2147798449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kakosidobrosam.gq" wide //weight: 1
        $x_1_2 = "Create" ascii //weight: 1
        $x_1_3 = "HttpWebRequest" ascii //weight: 1
        $x_1_4 = "GetResponse" ascii //weight: 1
        $x_1_5 = "GetResponseStream" ascii //weight: 1
        $x_1_6 = "StreamReader" ascii //weight: 1
        $x_1_7 = "TextReader" ascii //weight: 1
        $x_1_8 = "LazyInitializer" ascii //weight: 1
        $x_1_9 = "LoadLibrary" ascii //weight: 1
        $x_1_10 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_RPI_2147798450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.RPI!MTB"
        threat_id = "2147798450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "discord.gg/Y88gQ5e9px" wide //weight: 1
        $x_1_2 = "Siticone" ascii //weight: 1
        $x_1_3 = "VESTIGE LOGIN" wide //weight: 1
        $x_1_4 = "AUTHGG.dll" wide //weight: 1
        $x_1_5 = "UseShellExecute" ascii //weight: 1
        $x_1_6 = "CreateNoWindow" ascii //weight: 1
        $x_1_7 = "RunPE.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Downloader_RPI_2147798450_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.RPI!MTB"
        threat_id = "2147798450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 [0-128] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Stub.exe" wide //weight: 1
        $x_1_3 = "GetEnvironmentVariable" wide //weight: 1
        $x_1_4 = "Sleep" ascii //weight: 1
        $x_1_5 = "Thread" ascii //weight: 1
        $x_1_6 = "WebClient" ascii //weight: 1
        $x_1_7 = "DownloadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_CF_2147798708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.CF!MTB"
        threat_id = "2147798708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qq.exe" ascii //weight: 1
        $x_1_2 = "tim.exe" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "0.log" ascii //weight: 1
        $x_1_5 = "http://www.qq.com/%s/addinfo.asp" ascii //weight: 1
        $x_1_6 = "3.dll" ascii //weight: 1
        $x_1_7 = "HookDLL" ascii //weight: 1
        $x_1_8 = "vcon.key" ascii //weight: 1
        $x_1_9 = "QueryPerformanceCounter" ascii //weight: 1
        $x_1_10 = "1.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_CH_2147799135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.CH!MTB"
        threat_id = "2147799135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 d2 8a 17 30 da 88 17 47 39 cf 75 f3}  //weight: 1, accuracy: High
        $x_1_2 = {8a 07 90 47 90 2c e8 3c 01 77 f5 8b 07 90 8a 5f 04 86 c4 c1 c0 10 90 86 c4 29 f8 90 80 eb e8 01 f0 89 07 90 83 c7 05 90 88 d8 e2 db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_RPP_2147799178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.RPP!MTB"
        threat_id = "2147799178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0c 07 66 f7 c1 00 00 f7 c3 00 00 00 00 66 f7 c6 00 00 f7 c2 00 00 00 00 81 f1 af 58 73 c9 66 f7 c7 00 00 66 f7 c7 00 00 a9 00 00 00 00 31 0c 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_RPQ_2147799179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.RPQ!MTB"
        threat_id = "2147799179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 5d 00 3d a6 00 00 00 83 fb 75 e8 [0-16] [0-32] 01 1c 38 [0-32] [0-16] 81 ef [0-32] [0-16] 81 c7 [0-16] 0f 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_CK_2147799482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.CK!MTB"
        threat_id = "2147799482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a1 28 95 4f 00 83 c0 01 a3 28 95 4f 00 81 3d 28 95 4f 00 c8 1e ae 00 73 0d 68 a0 78 4f 00 ff 15 ?? ?? ?? ?? eb da}  //weight: 1, accuracy: Low
        $x_1_2 = {15 d2 bd 85 42 0a 81 b4 f0 06 00 83 30 0f 37 d1 d0 e2 7d}  //weight: 1, accuracy: High
        $x_1_3 = "VirtualUnlock" ascii //weight: 1
        $x_1_4 = "aswChLic.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_CAE_2147805268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.CAE!MTB"
        threat_id = "2147805268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Game_Y.exe" ascii //weight: 1
        $x_1_2 = "_GetDecryptProc@4" ascii //weight: 1
        $x_1_3 = "_GetEncryptProc@4" ascii //weight: 1
        $x_1_4 = "_SetDecryptionKey@4" ascii //weight: 1
        $x_1_5 = "Game.exe" ascii //weight: 1
        $x_1_6 = "http://www.jxqy1.com/news.html" ascii //weight: 1
        $x_1_7 = "trace.log" ascii //weight: 1
        $x_1_8 = "VirtualProtect" ascii //weight: 1
        $x_1_9 = "http://jx.kingsoft.com/tan.shtml" ascii //weight: 1
        $x_1_10 = "www.jxonline.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_CEB_2147806308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.CEB!MTB"
        threat_id = "2147806308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 11 73 b8 54 e2 3c 00 03 c5 81 c0 86 03 00 00 b9 c1 02 00 00 ba 39 ed 54 1b 30 10 40 49 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {bb 0c e2 20 50 98 15 14 f6 db 86 32 fb 49 33 41 76 57 e1 4d}  //weight: 1, accuracy: High
        $x_2_3 = "URLDownloadToFileW" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_CM_2147807567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.CM!MTB"
        threat_id = "2147807567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 c3 e9 dc e7 79 01 c3 81 eb e9 dc e7 79 01 0b}  //weight: 1, accuracy: High
        $x_1_2 = {05 04 00 00 00 33 04 24 31 04 24 33 04 24 5c 39 c2 0f 84}  //weight: 1, accuracy: High
        $x_2_3 = {81 f1 2a 5f ff 43 01 cb 59 81 eb 04 00 00 00 33 1c 24 31 1c 24 33 1c 24 5c 89 04 24 8f 45 f0 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_RPS_2147807729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.RPS!MTB"
        threat_id = "2147807729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 60 0e e3 4f 55 8d 44 24 60 c7 44 24 64 3c 2d 92 b8 c7 44 24 68 a8 05 37 ba c7 44 24 6c 6a 12 38 e0 0f 28 4c 24 60 68 ?? ?? ?? ?? c7 44 24 54 65 86 3d 3b c7 44 24 58 59 41 a1 8a c7 44 24 5c 86 61 5b d6 c7 44 24 60 6a 12 38 e0 66 0f ef 4c 24 54 50 6a 00 0f 29 4c 24 6c ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_CO_2147808320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.CO!MTB"
        threat_id = "2147808320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\TEMP\\setup.exe" ascii //weight: 1
        $x_1_2 = "setup_install.exe" ascii //weight: 1
        $x_1_3 = "%s%S.dll" ascii //weight: 1
        $x_1_4 = "!@InstallEnd@!7z" ascii //weight: 1
        $x_1_5 = "ExecuteFile" ascii //weight: 1
        $x_1_6 = "GetTickCount" ascii //weight: 1
        $x_1_7 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_TI_2147809029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.TI!MTB"
        threat_id = "2147809029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d0 81 f2 ?? ?? ?? ?? 03 55 0c 2b 15 ?? ?? ?? ?? 89 15}  //weight: 1, accuracy: Low
        $x_1_2 = {89 65 e8 81 f1 ?? ?? ?? ?? 83 c1 33 33 cf 83 c1 08 33 cb 89 0d}  //weight: 1, accuracy: Low
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_TA_2147809197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.TA!MTB"
        threat_id = "2147809197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 da d3 cb 33 c2 d3 c8 3b 5d f8 89 5d f0 8b 5d ec 75 05 3b 45 f4 74 af 8b 75 f0 8b f8 89 45 f4 eb a2}  //weight: 2, accuracy: High
        $x_1_2 = "http://wfsdragon.ru/api/setStats.php" ascii //weight: 1
        $x_1_3 = "http://37.0.10.214/proxies.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_BG_2147809316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.BG!MTB"
        threat_id = "2147809316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 45 99 33 85 ?? ?? ?? ?? b9 93 01 00 01 f7 e1 89 85 48 ff ff ff eb b1}  //weight: 1, accuracy: Low
        $x_1_2 = {03 42 1c 89 85 ?? ?? ?? ?? 8b 4d b0 8b 55 ac 03 51 24 89 95}  //weight: 1, accuracy: Low
        $x_1_3 = "pastebin.com" wide //weight: 1
        $x_1_4 = "212.193.30.29" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_BH_2147809317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.BH!MTB"
        threat_id = "2147809317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0a 83 c2 01 32 cb 74 40 83 e8 01 75 f2}  //weight: 1, accuracy: High
        $x_1_2 = "pastebin.com" wide //weight: 1
        $x_1_3 = "212.193.30.29" wide //weight: 1
        $x_1_4 = "wfsdragon.ru" wide //weight: 1
        $x_1_5 = "212.192.241.62" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_RPC_2147809352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.RPC!MTB"
        threat_id = "2147809352"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "185.121.177.177" ascii //weight: 1
        $x_1_2 = "69.164.196.21" ascii //weight: 1
        $x_1_3 = "159.89.120.99" ascii //weight: 1
        $x_1_4 = "51.254.25.115" ascii //weight: 1
        $x_1_5 = "167.99.39.23" ascii //weight: 1
        $x_1_6 = "Mozilla" ascii //weight: 1
        $x_1_7 = "AppleWebKit" ascii //weight: 1
        $x_1_8 = "/c bitsadmin /transfer" ascii //weight: 1
        $x_1_9 = "/download /priority high" ascii //weight: 1
        $x_1_10 = "Settings.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_RPD_2147809353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.RPD!MTB"
        threat_id = "2147809353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d6 68 dc 05 00 00 8b f8 ff 15 ?? ?? ?? ?? ff d6 2b c7 3d dc 05 00 00 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_RPE_2147809439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.RPE!MTB"
        threat_id = "2147809439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hacker" wide //weight: 1
        $x_1_2 = "pastebin.com" wide //weight: 1
        $x_1_3 = "Exploit" wide //weight: 1
        $x_1_4 = "WebClient" ascii //weight: 1
        $x_1_5 = "DownloadString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_RPF_2147809440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.RPF!MTB"
        threat_id = "2147809440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "secretlogs.xyz" wide //weight: 1
        $x_1_2 = "SilentCleanup" wide //weight: 1
        $x_1_3 = "cdn.discordapp.com" wide //weight: 1
        $x_1_4 = "WebBrowserPassView_update.exe" wide //weight: 1
        $x_1_5 = "WebClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_RPJ_2147809513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.RPJ!MTB"
        threat_id = "2147809513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 43 8b 32 42 42 42 42 8a 06 88 07 46 47 49 75 f7 0f b7 0b 81 f9 ?? ?? 00 00 72 e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_BI_2147809803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.BI!MTB"
        threat_id = "2147809803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 08 0f b6 1d ?? ?? ?? ?? 2b cb 81 e1 ?? ?? ?? ?? 79 08 49 81 c9 ?? ?? ?? ?? 41 88 08 40 4a 75 de}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 1c 01 33 1c 11 75 0a 83 c1 04 78 f3}  //weight: 1, accuracy: High
        $x_1_3 = "Payload Position" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "D:\\runner\\sources\\runner.dpr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_BJ_2147809807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.BJ!MTB"
        threat_id = "2147809807"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://167.99.39.23/hoetnaca/exps/Bt.mp4" ascii //weight: 1
        $x_1_2 = "%temp%\\Settings.exe" ascii //weight: 1
        $x_2_3 = "51.254.25.115" ascii //weight: 2
        $x_2_4 = "69.164.196.21" ascii //weight: 2
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Downloader_BO_2147810512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.BO!MTB"
        threat_id = "2147810512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Sample.exe" wide //weight: 1
        $x_1_2 = "exit_code.txt" wide //weight: 1
        $x_1_3 = "POWERSHELL" ascii //weight: 1
        $x_1_4 = "Run Sample v1" ascii //weight: 1
        $x_1_5 = "C:\\c_code\\helper\\windows\\executer\\Release\\executer.pdb" ascii //weight: 1
        $x_1_6 = "loaddll_x86.exe" wide //weight: 1
        $x_1_7 = "%s\\Shell\\Open\\Command" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_BP_2147811073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.BP!MTB"
        threat_id = "2147811073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 11 84 c0 74 09 3c 56 74 05 34 56 88 04 11 41 3b ce 7c eb}  //weight: 1, accuracy: High
        $x_1_2 = {8a 54 07 01 88 14 06 40 3b c1 7c f4}  //weight: 1, accuracy: High
        $x_1_3 = {80 f1 56 88 88 [0-4] 83 c0 06 3d [0-4] 0f 8c}  //weight: 1, accuracy: Low
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_BS_2147812740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.BS!MTB"
        threat_id = "2147812740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ad 51 8b 0f 4e 4e 33 c1 aa 4a 4e 8b c2 85 c0 75 07 ff 75 10 8b 55 14 5e 59 49 75 e4}  //weight: 1, accuracy: High
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_MG_2147814212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.MG!MTB"
        threat_id = "2147814212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 90 df ff ff 8a 08 88 8d 8b df ff ff 83 85 90 df ff ff 01 80 bd 8b df ff ff 00 75 e2 8b 95 90 df ff ff 2b 95 8c df ff ff 89 95 84 df ff ff 75}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 f0 88 08 8b 4d f0 83 c1 01 89 4d f0 8b 55 f8 0f b6 42 02 0f b6 88 ?? ?? ?? ?? c1 e1 06 8b 55 f8 0f b6 42 03 0f b6 ?? ?? ?? ?? ?? 0b ca 8b 45 f0 88 08 8b 4d f0 83 c1 01 89 4d f0 8b 55 f8 83 c2 04 89 55 f8 8b 45 f4 83 e8 04 89 45 f4 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_DA_2147815006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.DA!MTB"
        threat_id = "2147815006"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 45 ec 8b 45 ec 8a 04 30 8b 0d [0-4] 88 04 31 83 3d [0-4] 44 75 1d}  //weight: 2, accuracy: Low
        $x_2_2 = {3d 35 79 02 0f 7f 08 40 3d e2 51 62 73 7c f1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_AL_2147816306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.AL!MTB"
        threat_id = "2147816306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 10 80 f2 ?? 80 c2 ?? 88 10 83 c0 01 83 e9 01 75 e6}  //weight: 2, accuracy: Low
        $x_2_2 = "VirtualProtect" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Downloader_SAA_2147831415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downloader.SAA"
        threat_id = "2147831415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "agentpackagefileexplorer.exe" wide //weight: 1
        $x_1_2 = "agent-api.atera.com/production" wide //weight: 1
        $x_1_3 = "or8ixli90mf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

