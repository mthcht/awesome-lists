rule TrojanDownloader_Win32_Adload_2147766314_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload"
        threat_id = "2147766314"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 6c 00 75 00 63 00 6b 00 62 00 69 00 72 00 64 00 38 00 2e 00 63 00 6e 00 2f 00 00 00 00 00 18 00 00 00 74 00 74 00 68 00 68 00 33 00 2f 00 67 00 78 00 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: High
        $x_1_2 = "\\fpt.exe" wide //weight: 1
        $x_1_3 = "cmd.exe /c start" wide //weight: 1
        $x_1_4 = "\\Windows\\CuRRentVersion\\Run\\SoundMan" wide //weight: 1
        $x_1_5 = "SoundMan.exe" wide //weight: 1
        $x_1_6 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 6e 00 6f 00 74 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_2147766314_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload"
        threat_id = "2147766314"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{BC7DB684-3495-4201-85C5-7857F192B234}" ascii //weight: 1
        $x_1_3 = "korea.bonuspack.co.kr" ascii //weight: 1
        $x_1_4 = "81032FA7-5DFA-4814-ADA0-54E2F6B92BD0" ascii //weight: 1
        $x_1_5 = "FBC4906A-CEB0-4D36-9CE8-E9590109E4C6" ascii //weight: 1
        $x_1_6 = "DllRegisterServer" ascii //weight: 1
        $x_1_7 = "FindNextFileA" ascii //weight: 1
        $x_1_8 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_9 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_10 = "gethostbyname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_BO_2147799760_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.BO"
        threat_id = "2147799760"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 ff 45 fc 81 7d fc e8 03 00 00 7d 4b 83 3d ?? ?? ?? ?? 00 75 42 68 30 75 00 00 ff 15 ?? ?? ?? ?? eb 80 e8 ?? ?? ?? ?? 6a 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {68 d0 07 00 00 ff 15 ?? ?? ?? ?? 83 fe 04 75 01 90 81 fe 08 07 00 00 75 01 90 46 83 7d fc 00 0f 85 ?? ?? ?? ?? 33 c0 5e c9 c2 10 00 83 c8 ff eb f6}  //weight: 1, accuracy: Low
        $x_1_3 = ".niudoudou.com/web/download/" ascii //weight: 1
        $x_1_4 = {67 65 74 5f 61 64 [0-1] 2e 61 73 70 3f 74 79 70 65 3d 6c 6f 61 64 61 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_E_2147800127_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.E"
        threat_id = "2147800127"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "down.xiald.com" ascii //weight: 1
        $x_1_2 = "downcdn.xiald.com" ascii //weight: 1
        $x_1_3 = "tjv1.xiald.com" ascii //weight: 1
        $x_1_4 = {3a 5c 58 69 61 5a 61 69 51 69 5c 70 64 62 6d 61 70 5c 57 61 6e 4e 65 6e 67 5c 49 6e 73 74 61 6c 6c 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_CZ_2147800844_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.CZ"
        threat_id = "2147800844"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1}  //weight: 5, accuracy: High
        $x_1_2 = "pops.go-diva.co.kr/hantiat" ascii //weight: 1
        $x_1_3 = "pops.go-diva.co.kr/hantiat" wide //weight: 1
        $x_1_4 = "Win Search forhantiat" ascii //weight: 1
        $x_1_5 = "pops/logs.v" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Adload_BA_2147801355_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.BA"
        threat_id = "2147801355"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.alxu" ascii //weight: 1
        $x_1_2 = {69 63 65 50 72 6f 63 65 73 73 00 00 4b 45 52 4e 45 4c 33 32 00 00 00 00 5c 41 64 73 4e 54 2e 65 78 65 00 00 41 64 73 4e 54 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_BP_2147801465_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.BP"
        threat_id = "2147801465"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/count_live.asp?exec=" ascii //weight: 1
        $x_1_2 = ".easyenco.co.kr/module/count.asp?exec=" ascii //weight: 1
        $x_1_3 = {2f 2f 2a 5b 40 72 61 6e 6b 20 3d 20 27 00 00 00 25 64 2d 25 64 2d 25 64 00 00 00 00 25 59 2d 25 6d 2d 25 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_BM_2147802636_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.BM!dll"
        threat_id = "2147802636"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "&u_his=1&u_java=true&u_nplug=0&u_nmime=0&frm=0" ascii //weight: 1
        $x_1_2 = "%s\\ab%d%d%d.tmp" ascii //weight: 1
        $x_1_3 = "%s\\1028\\ieversion.ini" ascii //weight: 1
        $x_1_4 = {68 10 27 00 00 ff ?? a1 ?? ?? ?? ?? 83 f8 03 74 05 83 f8 01 75 ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Adload_DN_2147803121_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.DN"
        threat_id = "2147803121"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/log/Outsurfing_IC/install" wide //weight: 1
        $x_1_2 = "54.214.246.97/" wide //weight: 1
        $x_1_3 = "start: 1.0.1.2" wide //weight: 1
        $x_1_4 = "ERR: Virtual PC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_BE_2147803270_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.BE"
        threat_id = "2147803270"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 6f 67 6f 6e 4e 61 6d 65 [0-5] 53 4f 46 54 57 41 52 45 5c 53 6f 66 74 66 79 5c 50 6c 75 67 4e 61 6d 65}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 69 61 6e 6d 2e 63 6f 6d 2f 4d 61 69 6e 44 6c 6c 2f 53 6f 66 74 53 69 7a 65 2e 61 73 70 [0-10] 46 69 6e 64 20 66 6c 79 20 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {49 6e 73 74 61 6c 6c 4d 79 44 6c 6c [0-5] 72 75 6e 64 6c 6c 33 32}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 66 6c 79 6d 79 2e 64 6c 6c [0-5] 53 65 72 76 65 72 46 69 6c 65 53 69 7a 65 3d 25 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_B_2147803379_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.B"
        threat_id = "2147803379"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ztds2.online" wide //weight: 1
        $x_1_2 = "http://www.applicablebeam.com/ddawdew/trjgje.exe" wide //weight: 1
        $x_1_3 = "http://www.sectorappliance.com/qdewfww/kdjase.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_DG_2147803661_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.DG"
        threat_id = "2147803661"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "d_c_b_p__" wide //weight: 5
        $x_5_2 = {5c 6b 69 6c 6c 61 2e 65 78 65 00}  //weight: 5, accuracy: High
        $x_5_3 = {74 65 6d 70 25 30 32 64 2e 65 78 65 00}  //weight: 5, accuracy: High
        $x_5_4 = {74 65 6d 70 25 30 33 64 2e 7a 69 70 00}  //weight: 5, accuracy: High
        $x_1_5 = {77 77 77 2e 61 64 62 6f 6e 73 6b 69 6c 6c 67 61 6d 65 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_6 = {77 77 77 2e 76 61 64 73 6b 69 6c 6c 67 61 6d 65 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_7 = {77 77 77 2e 76 61 64 63 65 6e 74 65 72 67 61 6d 65 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_8 = {77 77 77 2e 35 6e 69 75 78 78 2e 63 6f 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Adload_AU_2147803818_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.AU"
        threat_id = "2147803818"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dl/dluniq1.php?adv=" ascii //weight: 1
        $x_1_2 = "Allow all activities for this application" ascii //weight: 1
        $x_1_3 = {74 6f 6f 6c 62 61 72 2e 74 78 74 00 5c 74 6f 6f 6c 34 2e 65 78 65 00 00 5c 74 6f 6f 6c 32 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion" ascii //weight: 1
        $x_1_5 = "&Remember this answer the next time I use this program." ascii //weight: 1
        $x_1_6 = {26 63 6f 64 65 31 3d 48 4e 4e 45 [0-1] 26 63 6f 64 65 32 3d 35 31 32 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_L_2147803837_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.L"
        threat_id = "2147803837"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 2e 66 6c 76 00 00 00 75 2e 62 6d 70 00 00 00 64 2e 65 78 65 00 00 00 72 2e 64 6c 6c 00 00 00 73 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_2 = {42 48 4f 2e 46 75 6e 50 6c 61 79 65 72 00 00 00 7b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_BB_2147803838_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.BB"
        threat_id = "2147803838"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 70 2d 6d 79 64 61 74 65 2e 70 68 70 00 00 00 73 6f 66 74 77 61 72 65 5c}  //weight: 1, accuracy: High
        $x_1_2 = {2d 6d 79 00 74 6f 74 61 6c 00 00 00 5c 54 65 6d 70 5c 00 00 4e 69 6e 66 6f 2e 64 61 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_A_2147803854_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.gen!A"
        threat_id = "2147803854"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Stopping %s." ascii //weight: 5
        $x_5_2 = "SetServiceStatus() failed" ascii //weight: 5
        $x_5_3 = "RegisterServiceProcess" ascii //weight: 5
        $x_5_4 = "GetLastActivePopup" ascii //weight: 5
        $x_5_5 = "\\system\\regsvr32.exe" ascii //weight: 5
        $x_1_6 = "player.dll" ascii //weight: 1
        $x_1_7 = "mshtmlsed.exe" ascii //weight: 1
        $x_1_8 = "FP30IE.dll" ascii //weight: 1
        $x_1_9 = "FP30PY.dll" ascii //weight: 1
        $x_1_10 = "FP30SVR.exe" ascii //weight: 1
        $x_1_11 = "play.dll" ascii //weight: 1
        $x_1_12 = "bho.dll" ascii //weight: 1
        $x_1_13 = "2810BB9D466D}" ascii //weight: 1
        $x_1_14 = "71572690-1156-4e36-9F2A-42587899ABDE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Adload_B_2147803904_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.gen!B"
        threat_id = "2147803904"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "//www.MoKeAD.c" ascii //weight: 1
        $x_1_2 = "//w1.MoKeAD.c" ascii //weight: 1
        $x_1_3 = "//w2.MoKeAD.c" ascii //weight: 1
        $x_1_4 = "//w3.MoKeAD.c" ascii //weight: 1
        $x_1_5 = "//w4.MoKeAD.c" ascii //weight: 1
        $x_1_6 = "//w5.MoKeAD.c" ascii //weight: 1
        $x_1_7 = "SerSetup.exe" ascii //weight: 1
        $x_1_8 = {43 68 65 63 6b 55 70 64 61 74 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 62 61 6b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_BQ_2147803951_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.BQ"
        threat_id = "2147803951"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 50 fe 4c fe 48 fe 44 fe 40 fe 3c fe 38 fe 34 fe 30 fe 2c fe 28 fe 24 fe 20 fe 1c fe}  //weight: 1, accuracy: High
        $x_1_2 = {04 1a fd 04 58 ff 3a 44 ff ?? 00 04 b4 fd fb ef 34 ff 04 d4 fd fb ef 14 ff 60 fd c7 50 fe 10 f8 06 ?? 00 6b 1a fd 2f 50 fe 36 04 00 34 ff 14 ff 1c 27 05 00 27 f5 03 00 00 00 6c 58 ff 1b ?? 00 2a 46 34 ff 04 6c ff fb ef 14 ff 0a ?? 00 08 00 74 10 fd 36 04 00 34 ff 14 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_BQ_2147803951_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.BQ"
        threat_id = "2147803951"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 83 f9 2d 74 06 66 83 f9 2f 75 28 0f b7 48 02 66 83 f9 6f 74 17 66 83 f9 4f 74 11 66 83 f9 72 75 12 83 c0 04}  //weight: 1, accuracy: High
        $x_1_2 = {66 8b 48 02 83 c0 02 66 85 c9 75 f4 8b 0d ?? ?? 40 00 8b 15 ?? ?? 40 00 89 08 8b 0d ?? ?? 40 00 89 50 04 8b 15 ?? ?? 40 00 89 48 08 89 50 0c}  //weight: 1, accuracy: Low
        $x_1_3 = "%s\\window%d.tmp" wide //weight: 1
        $x_1_4 = {64 00 32 00 2e 00 78 00 69 00 61 00 7a 00 68 00 61 00 69 00 38 00 2e 00 6e 00 65 00 74 00 2f 00 3f 00 69 00 64 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? 26 00 32 00 37 00 33 00 38 00 36 00 36 00 36 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_CU_2147803977_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.CU"
        threat_id = "2147803977"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 72 6f 64 75 63 74 4e 61 6d 65 [0-48] 77 69 6e 64 6f 77 73 20 37 [0-16] 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 41 68 6e 4c 61 62 5c 56 33 4c 69 74 65 5c 56 33 4c 69 67 68 74 2e 65 78 65 [0-16] 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4e 61 76 65 72 5c 4e 61 76 65 72 56 61 63 63 69 6e 65 5c 4e 56 43 55 70 67 72 61 64 65 72 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {74 07 c7 45 ?? 04 00 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 07 c7 45 ?? 04 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {83 f8 02 7d ?? 68 ?? ?? ?? ?? ff 75 ?? 68 [0-48] 8d 55 ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 75 ?? 8d 45 ?? ba ?? 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_A_2147804023_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.A"
        threat_id = "2147804023"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 70 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e 00}  //weight: 10, accuracy: High
        $x_10_2 = {57 69 6e 41 75 74 6f 55 70 00}  //weight: 10, accuracy: High
        $x_1_3 = {53 55 57 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? 00 bd 01 00 00 00 ff 15 ?? ?? ?? 00 8b d8 85 db 89 5c 24 14 0f ?? ?? 00 00 00 8b 84 24 2c 04 00 00 6a 00 68 00 01 00 84 6a 00 6a 00 50 53 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_4 = {53 55 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? 00 bd 01 00 00 00 ff 15 ?? ?? ?? 00 8b d8 85 db 89 5c 24 0c 0f ?? ?? 00 00 00 8b 84 24 14 04 00 00 57 6a 00 68 00 01 00 84 6a 00 6a 00 50 53 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Adload_AY_2147804060_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.AY"
        threat_id = "2147804060"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.alxu" ascii //weight: 1
        $x_1_2 = {69 63 65 50 72 6f 63 65 73 73 00 00 4b 45 52 4e 45 4c 33 32 00 00 00 00 5c 41 64 73 4e 54 2e 65 78 65 00 00 41 64 73 4e 54 00 00 00 56 65 72 73 69 6f 6e 00 73 4e 54 2e 69 6e 69 00 5c 41 64 00 5c 69 6e 64 65 78 2e 68 74 6d 00 00 0d 0a 0d 0a 00 00 00 00 52 65 66 65 72 65 72 3a 20 00 00 00 61 64 73 6e 74 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 70 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e 00 77 62 00 00 61 64 73 6e 74 44 2f 31 2e 39 00 00 41 64 73 4e 54 47 72 6f 75 70 55 52 4c 00 00 00 67 75 72 6c 25 64 25 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_AZ_2147804061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.AZ"
        threat_id = "2147804061"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f7 8b d9 8b fa 83 c9 ff f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 8d 94 24 1c 01 00 00 83 e1 03 f3 a4 bf ?? ?? ?? ?? 83 c9 ff f2 ae f7 d1 2b f9 8b f7 8b d9 8b fa 83 c9 ff f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 8d 84 24 1c 01 00 00 83 e1 03 50 f3 a4}  //weight: 1, accuracy: Low
        $x_1_2 = "http://download.powercreator" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{5B02EBA1-EFDD-477D-A37F-05383165C9C0}" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\Run" ascii //weight: 1
        $x_1_5 = "AutoUp.exe" ascii //weight: 1
        $x_1_6 = "http://www.alxup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_H_2147804087_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.H"
        threat_id = "2147804087"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 41 51 8d 55 ?? 8b cc 89 a5 ?? ff ff ff 52 e8 ?? ?? 00 00 8b ce e8 ?? ?? ff ff 8b 4d ?? 8d 85 ?? ?? ff ff 6a 01 50 6a 00 51 68 ?? ?? 40 00 6a 00 ff 15 ?? ?? 40 00 8d 4d ?? c6 45 fc 3a}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 fc 9b e8 ?? ?? ff ff 6a 2f 8d 8d ?? ff ff ff c6 45 fc 9d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_BF_2147804131_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.BF"
        threat_id = "2147804131"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 6f 67 6f 6e 4e 61 6d 65 00 00 00 53 4f 46 54 57 41 52 45 5c 53 6f 66 74 66 79 5c 50 6c 75 67 4e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 66 79 65 64 69 74 2e 63 6e 2f 4d 61 69 6e 44 6c 6c 2f 53 6f 66 74 53 69 7a 65 2e 61 73 70 00 00 00 46 69 6e 64 20 66 6c 79 20 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {49 6e 73 74 61 6c 6c 4d 79 44 6c 6c 00 72 75 6e 64 6c 6c 33 32 20 20 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 66 6c 79 6d 79 2e 64 6c 6c 00 00 53 65 72 76 65 72 46 69 6c 65 53 69 7a 65 3d 25 64 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_BH_2147804132_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.BH"
        threat_id = "2147804132"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 6f 67 6f 6e 4e 61 6d 65 00 00 00 53 4f 46 54 57 41 52 45 5c 53 6f 66 74 66 79 5c 50 6c 75 67 4e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 66 79 68 61 70 70 79 2e 63 6e 2f 4d 61 69 6e 44 6c 6c 2f 53 6f 66 74 53 69 7a 65 2e 61 73 70 00 00 46 69 6e 64 20 66 6c 79 20 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {49 6e 73 74 61 6c 6c 4d 79 44 6c 6c 00 72 75 6e 64 6c 6c 33 32 20 20 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 66 6c 79 6d 79 2e 64 6c 6c 00 53 65 72 76 65 72 46 69 6c 65 53 69 7a 65 3d 25 64 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_CI_2147804177_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.CI"
        threat_id = "2147804177"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 6a 00 70 00 64 00 65 00 73 00 6b 00 5f 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 2f 00 64 00 6c 00 63 00 61 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {ba 02 00 00 80 8b 45 e0 e8 ?? ?? ?? ?? b1 01 ba ?? ?? ?? ?? 8b 45 e0 e8 ?? ?? ?? ?? 84 c0 74 12 b9 02 00 00 00 ba ?? ?? ?? ?? 8b 45 e0 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_CS_2147804191_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.CS"
        threat_id = "2147804191"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "http://www.niudoudou.com/web/download/" ascii //weight: 4
        $x_2_2 = "%s%s&machinename=%s" ascii //weight: 2
        $x_3_3 = "get_ad.asp?type=loadall" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_BL_2147804201_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.BL"
        threat_id = "2147804201"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 65 64 69 61 75 70 64 74 2e 65 78 65 00 64 6f 77 6e 6c 6f 61 64 00 6d 65 64 69 61 63 68 63 6b 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "mediamedialtd.in/media" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_CX_2147804222_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.CX"
        threat_id = "2147804222"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {70 68 70 3f 6d 3d ?? 26 6d 61 63 3d 3a 6d 61 63 26 66 3d 3a 66 69 6c 65}  //weight: 2, accuracy: Low
        $x_1_2 = "$$336699.bat" ascii //weight: 1
        $x_1_3 = {ba 44 00 00 00 e8 ?? ?? ?? ff c7 85 08 fe ff ff 01 00 00 00 66 c7 85 0c fe ff ff 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_BX_2147804233_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.BX"
        threat_id = "2147804233"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 61 72 06 3c 7a 77 02 2c 20 c3}  //weight: 1, accuracy: High
        $x_1_2 = {2e 74 6d 70 00 00 04 00 5c}  //weight: 1, accuracy: Low
        $x_1_3 = "http@:/$/c@wno@vt.c" ascii //weight: 1
        $x_1_4 = "r@e$fu$rl$=" ascii //weight: 1
        $x_1_5 = "r@e$fu@rl=" ascii //weight: 1
        $x_1_6 = "re@fu$rl@=" ascii //weight: 1
        $x_1_7 = "R@e$fe$r$er" ascii //weight: 1
        $x_1_8 = "&s@oc@k$=$1" ascii //weight: 1
        $x_1_9 = "Mo@zi$lla" ascii //weight: 1
        $x_1_10 = "si$d@eb@ar_cl@i@ck$.a@sp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_Win32_Adload_BU_2147804259_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.BU"
        threat_id = "2147804259"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 14 68 59 02 00 00 ff d5 68 93 01 00 00 ff d5 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c4 04 84 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "~1\\suoyouxins.bat" ascii //weight: 1
        $x_1_3 = "~1\\haoyru.txt yuieie.exe" ascii //weight: 1
        $x_1_4 = "pd.natanlm.cn/x0606/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_BZ_2147804263_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.BZ"
        threat_id = "2147804263"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&s@o+m*^++*a^+c@k$=+m*^++*a^+$1" ascii //weight: 1
        $x_1_2 = "?bn$=+*a^+0@+m*^+&q@y=" ascii //weight: 1
        $x_1_3 = "lo+m*^+cati+m*^+on.rep+m*^+lace(" ascii //weight: 1
        $x_1_4 = "si$d@+m*^+eb+*a^+@ar_cl+m*^+@i+*a^+@ck$.a+*a^+@sp" ascii //weight: 1
        $x_1_5 = "o@v+*a^++m*^+e$rt@l$2.c$+*a^++m*^+o@m/@o+*a^++m*^+$sl$2/o@vn+m*^+@_o.a@sp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_CA_2147804264_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.CA"
        threat_id = "2147804264"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "&sock=1" ascii //weight: 1
        $x_1_2 = "sidebar_click.asp" ascii //weight: 1
        $x_1_3 = "/s@id@eba@r.a@s$p?b@n=$0&q$y=" ascii //weight: 1
        $x_1_4 = {2f 2f 6f 24 76 40 65 72 74 40 [0-3] 2e 63 6f 6d 2f 6f ?? ?? ?? 2f 6f 76 6e 5f 6f 2e 61 40 73 24 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_CC_2147804267_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.CC"
        threat_id = "2147804267"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 30 75 00 00 ff 15 ?? ?? ?? ?? 8b 85 e8 ea ff ff 83 c6 02 e9 6d ff ff ff b8 ?? ?? ?? ?? c3 33 db 53 e8 ?? ?? ?? ?? 68 40 1f 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = ".bcjjgc.com" ascii //weight: 1
        $x_1_3 = "\\GameVersionUpdate1\\" ascii //weight: 1
        $x_1_4 = "\\Windows NT\\sms_log.txt" ascii //weight: 1
        $x_1_5 = "/stat.wamme.cn/C8C/gl/cnzz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_CD_2147804268_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.CD"
        threat_id = "2147804268"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "LinuxStat.gamedia.cn/Start" ascii //weight: 3
        $x_3_2 = "\\NewGameUpdate\\GameVersionUpdate.temp" ascii //weight: 3
        $x_3_3 = {2f 43 38 43 5f 49 4e 49 2f 47 61 6d 65 56 65 72 73 69 6f 6e 55 70 64 61 74 65 [0-1] 2e 74 78 74}  //weight: 3, accuracy: Low
        $x_1_4 = "/run.hygame8888.cn/" ascii //weight: 1
        $x_1_5 = "/video.urlservice.cn/" ascii //weight: 1
        $x_1_6 = {2f 65 64 6f 6e 6b 65 79 73 65 72 76 65 72 ?? 2e 38 38 30 30 2e 6f 72 67 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Adload_CE_2147804269_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.CE"
        threat_id = "2147804269"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "LinuxStat.gamedia.cn" ascii //weight: 3
        $x_3_2 = "\\GameVersionUpdate\\GameVersionUpdate.temp" ascii //weight: 3
        $x_3_3 = {2f 43 38 43 5f 49 4e 49 2f 47 61 6d 65 56 65 72 73 69 6f 6e 55 70 64 61 74 65 [0-1] 2e 74 78 74}  //weight: 3, accuracy: Low
        $x_1_4 = ".ca8.com.cn/" ascii //weight: 1
        $x_1_5 = "heiying1976.com/" ascii //weight: 1
        $x_1_6 = {2f 65 64 6f 6e 6b 65 79 73 65 72 76 65 72 ?? 2e 38 38 30 30 2e 6f 72 67 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Adload_CF_2147804270_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.CF"
        threat_id = "2147804270"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "LinuxStat.gamedia.cn" ascii //weight: 1
        $x_1_2 = "startup.exe" ascii //weight: 1
        $x_1_3 = "\\JinZQ\\Hook" ascii //weight: 1
        $x_1_4 = "/run.hygame8888.cn/" ascii //weight: 1
        $x_1_5 = "/video.urlservice.cn/" ascii //weight: 1
        $x_1_6 = {2f 65 64 6f 6e 6b 65 79 73 65 72 76 65 72 ?? 2e 38 38 30 30 2e 6f 72 67 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Adload_CG_2147804271_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.CG"
        threat_id = "2147804271"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 00 45 fe 33 c0 38 45 fe 74 08 38 45 ff 74 03}  //weight: 1, accuracy: High
        $x_1_2 = "Run successfully~" ascii //weight: 1
        $x_1_3 = "1Pb94ucCAJ8=" ascii //weight: 1
        $x_1_4 = "0tHb4/z0/fv8/gPT/OX2+wLenw==" ascii //weight: 1
        $x_1_5 = "9/Pz76m8vAP89P29sLWv8P4FAr0A/Pq89v3w870C5wKf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_CN_2147804272_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.CN"
        threat_id = "2147804272"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".bcjjgc.com" ascii //weight: 1
        $x_1_2 = " NT\\sms_log.txt" ascii //weight: 1
        $x_1_3 = "\\GameVersionUpdate1\\" ascii //weight: 1
        $x_1_4 = "edonkeyserver2.8800.org/ExeIni/" ascii //weight: 1
        $x_1_5 = "pub.hygame8888.cn/c8c_ini/GameVersionUpdate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_DP_2147804274_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.DP!bit"
        threat_id = "2147804274"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_2 = {2f 4e 4f 43 41 4e 43 45 4c 00 2f 53 49 4c 45 4e 54 00 67 65 74 00 fd 9a 80 5c}  //weight: 1, accuracy: High
        $x_1_3 = "/launch_reb.php?p=sevenzip&tid=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_DS_2147804275_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.DS!bit"
        threat_id = "2147804275"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 14 8a 02 88 45 fc 8b 4d 14 83 c1 01 89 4d 14 ba ?? ?? ?? 00 03 55 08 8b 45 0c 03 45 08 8b 0d ?? ?? ?? 00 8b 35 ?? ?? ?? 00 8a 14 32 88 14 08 8b 45 0c 03 45 08 8b 0d ?? ?? ?? 00 8a 14 08 32 55 fc 8b 45 0c 03 45 08 8b 0d ?? ?? ?? 00 88 14 08 8b 55 08 83 c2 01 89 55 08}  //weight: 1, accuracy: Low
        $x_1_2 = {83 3c 31 ff 75 15 ba ?? ?? ?? 00 c6 42 0a 90 a1 ?? ?? ?? 00 c7 04 30 55 8b ec 6a}  //weight: 1, accuracy: Low
        $x_1_3 = {57 cc b9 0f 00 00 00 33 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_DT_2147804276_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.DT!bit"
        threat_id = "2147804276"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "slip.seatomatoes.bid/stats.php?bu=" ascii //weight: 2
        $x_2_2 = {00 61 72 5f 75 72 6c 00 61 72 5f 73 69 6c 65 6e 74 00 61 72 5f 62 75 6e 64 6c 65 00 61 72 5f 6d 65 73 73 61 67 65 00}  //weight: 2, accuracy: High
        $x_1_3 = {00 2f 53 49 4c 45 4e 54 00 67 65 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 64 6f 77 6e 6c 6f 61 64 5f 71 75 69 65 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Adload_DU_2147804277_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.DU!bit"
        threat_id = "2147804277"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fd 9a 80 5c 49 4e 65 74 43 2e 64 6c 6c 00 2f 45 4e 44 00 68 74 74 70 3a 2f 2f 77 77 77 2e 70 61 70 61 70 69 6e 67 2e 63 6f 6d}  //weight: 1, accuracy: High
        $x_1_2 = {00 2f 75 73 65 72 61 67 65 6e 74 00 2f 4e 4f 50 52 4f 58 59 00 67 65 74 00 4f 4b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_DU_2147804277_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.DU!bit"
        threat_id = "2147804277"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 05 30 00 00 00 8b 40 0c 8b 40 1c 8b 00 8b 40 08 a3 ?? ?? ?? 00 8d 45 fc ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8d 45 f8 ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8d 4d ?? 8b 55 fc 8b 45 f8 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 fc 8b 55 f8 8a 54 32 ff 32 da 88 5c 30 ff 46 4f 75 90}  //weight: 1, accuracy: High
        $x_1_3 = {6a 05 6a 00 8b 03 e8 ?? ?? ?? ff 50 8d 85 ?? ff ff ff 8b 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 85 ?? ff ff ff e8 ?? ?? ?? ff 50 68 ?? ?? ?? 00 6a 00 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_DR_2147804278_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.DR!bit"
        threat_id = "2147804278"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://s3-us-west-2.amazonaws.com/elasticbeanstalk-us-west-2-143692468872/Installer.exe" ascii //weight: 1
        $x_1_2 = {6d 79 66 69 6c 65 73 64 6f 77 6e 6c 6f 61 64 2e 63 6f 6d 2f [0-64] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_DR_2147804278_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.DR!bit"
        threat_id = "2147804278"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 ec 1c 8b cc 89 a5 cc fe ff ff 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b cc 89 a5 cc fe ff ff 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8}  //weight: 5, accuracy: Low
        $x_3_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 72 00 65 00 61 00 64 00 6c 00 65 00 6e 00 74 00 61 00 2e 00 72 00 75 00 2f 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 3, accuracy: Low
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 64 00 61 00 6e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 63 00 6c 00 65 00 76 00 65 00 72 00 61 00 64 00 64 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Adload_DX_2147804279_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.DX!bit"
        threat_id = "2147804279"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 77 65 73 74 2d 32 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 2f [0-80] 2f 4a 61 77 5a 69 67 61 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "{tmp}\\JawZiga.exe" ascii //weight: 1
        $x_1_3 = {00 2e 63 6f 6e 66 69 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_DX_2147804279_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.DX!bit"
        threat_id = "2147804279"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "gold.powerstring.bid/stats.php?bu=" ascii //weight: 1
        $x_1_2 = {62 75 6e 2e 77 61 72 73 70 61 64 65 2e 62 69 64 2f 6c 61 75 6e 63 68 5f 76 ?? 2e 70 68 70 3f 70 3d 26 70 69 64 3d [0-16] 26 74 69 64 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {77 69 6e 2e 65 67 67 73 77 69 6c 64 65 72 6e 65 73 73 2e 62 69 64 2f 6c 61 75 6e 63 68 5f 76 ?? 2e 70 68 70 3f 70 3d 26 70 69 64 3d [0-16] 26 74 69 64 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_B_2147804281_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.B!MSR"
        threat_id = "2147804281"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "JJDownLoader\\Bin\\JJDownLoader_a.pdb" ascii //weight: 1
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-32] 2f 00 67 00 65 00 74 00 73 00 6f 00 66 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Adload_DK_2147804282_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.DK!bit"
        threat_id = "2147804282"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/VERYSILENT" ascii //weight: 1
        $x_1_2 = "/kL3CuYDWuF/Yx5cJur3eX/jfk0021.exe" ascii //weight: 1
        $x_1_3 = "DOWNLOADANDEXECUTE" ascii //weight: 1
        $x_1_4 = "class:TCONTROL|HIDE|" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_DL_2147804283_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.DL!bit"
        threat_id = "2147804283"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 b4 05 b0 fb ff ff 54 40 83 f8 0b 72 f2}  //weight: 1, accuracy: High
        $x_1_2 = {80 b4 05 b0 fb ff ff 54 40 83 f8 0f 72 f2}  //weight: 1, accuracy: High
        $x_1_3 = {80 b4 05 50 fb ff ff 54 40 83 f8 11 72 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_DV_2147804284_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.DV!bit"
        threat_id = "2147804284"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".php?p=sevenzip&tid=" ascii //weight: 2
        $x_2_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 00 57 69 6e 64 6f 77 73 20 52 65 66 72 65 73 68 00}  //weight: 2, accuracy: High
        $x_1_3 = {00 2f 53 49 4c 45 4e 54 00 67 65 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 64 6f 77 6e 6c 6f 61 64 5f 71 75 69 65 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Adload_DW_2147804285_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.DW!bit"
        threat_id = "2147804285"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 77 65 73 74 2d 32 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 2f [0-80] 2f 4d 65 7a 72 69 67 69 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {00 2e 63 6f 6e 66 69 67}  //weight: 1, accuracy: High
        $x_1_3 = "{tmp}\\Mezrigi.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_DHE_2147804289_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.DHE!MTB"
        threat_id = "2147804289"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://i.ttd7.cn/getsoft" ascii //weight: 1
        $x_1_2 = "http://down.firmsoar.com/Fastaide_1160.exe" ascii //weight: 1
        $x_1_3 = "KuaiZip_Setup_3087616459_ytd_002.exe" ascii //weight: 1
        $x_1_4 = "http://download.kaobeitu.com/kaobeitu/" ascii //weight: 1
        $x_1_5 = "\\JJDownLoader\\Bin\\JJDownLoader_a.pdb" ascii //weight: 1
        $x_1_6 = "{reg:HKCU\\Software\\KuaiZip\\Install,Path}\\KzNew.dat" ascii //weight: 1
        $x_1_7 = "http://download.zjsyawqj.cn/jjbq/setup_jjbq_jjbq03nodkpk_v1.0_silent.exe" ascii //weight: 1
        $x_1_8 = "{commonappdata}\\<{$random}>\\{computername}.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_Win32_Adload_AG_2147804290_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.AG!MTB"
        threat_id = "2147804290"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 04 01 88 45 ?? 0f b6 45 ?? 8b 4d ?? 0f b6 4c 0d ?? 33 c1 8b 4d ?? 8b 55 ?? 88 04 0a 25 00 8b 45 ?? 40 89 45 ?? 8b 45 ?? 39 45 ?? 73 ?? 8b 4d ?? c1 e1 ?? 8b 45 ?? 33 d2 f7 f1 89 55 ?? 8b 45 ?? 8b 4d}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_SB_2147804292_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.SB!MSR"
        threat_id = "2147804292"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Release\\adviser.pdb" ascii //weight: 1
        $x_2_2 = "http://yasovetn1k.ru/files/" wide //weight: 2
        $x_1_3 = "payout" wide //weight: 1
        $x_1_4 = "temp_directory_path()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Adload_AMK_2147804299_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.AMK!MTB"
        threat_id = "2147804299"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SysListView32" ascii //weight: 3
        $x_3_2 = "yapp.exe" ascii //weight: 3
        $x_3_3 = "ShellExecuteExW" ascii //weight: 3
        $x_3_4 = "ExpandEnvironmentStringsW" ascii //weight: 3
        $x_3_5 = "[Rename]" ascii //weight: 3
        $x_3_6 = "%ls=%ls" ascii //weight: 3
        $x_3_7 = "ExecuteFile" ascii //weight: 3
        $x_3_8 = "unknowndll.pdb" ascii //weight: 3
        $x_3_9 = "EMP\\nsk" ascii //weight: 3
        $x_3_10 = "@pp.exe" ascii //weight: 3
        $x_3_11 = "%s%S.dll" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_AMK_2147804299_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.AMK!MTB"
        threat_id = "2147804299"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Embarcadero RAD Studio" ascii //weight: 3
        $x_3_2 = "DbgPrompt" ascii //weight: 3
        $x_3_3 = "DllInstall" ascii //weight: 3
        $x_3_4 = "borlndmm" ascii //weight: 3
        $x_3_5 = "KillTimer" ascii //weight: 3
        $x_3_6 = "Stub.exe" ascii //weight: 3
        $x_3_7 = "DbgQueryDebugFilterState" ascii //weight: 3
        $x_3_8 = "NtNotifyChangeKey" ascii //weight: 3
        $x_3_9 = "LdrUnlockLoaderLock" ascii //weight: 3
        $x_3_10 = "SimplySync Backup" ascii //weight: 3
        $x_3_11 = "fyChangeKey" ascii //weight: 3
        $x_3_12 = "kLoaderLock" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adload_SIBI_2147808224_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adload.SIBI!MTB"
        threat_id = "2147808224"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://otisrebe.xyz/FastPC.exe" ascii //weight: 10
        $x_10_2 = "FastPCRAW" ascii //weight: 10
        $x_1_3 = "itdownload.dll" ascii //weight: 1
        $x_1_4 = "itd_downloadfile" ascii //weight: 1
        $x_1_5 = "itd_clearfiles" ascii //weight: 1
        $x_1_6 = "{sysuserinfoname}" ascii //weight: 1
        $x_1_7 = "{sysuserinfoorg}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

