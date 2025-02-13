rule TrojanDownloader_Win32_Agent_VT_2147800004_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.VT"
        threat_id = "2147800004"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "121"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "system32\\regsvr32 /s " ascii //weight: 100
        $x_10_2 = {40 40 00 55 8b 2d ?? ?? 40 00 56 8b 74 24 10 57 8b 3d ?? ?? 40 00 68 ?? ?? 40 00 ff d3 68 ?? ?? ?? ?? ff d7 8b ce e8 ?? ?? 00 00 85 c0 75 0b 8b ce e8 ?? ?? 00 00 85 c0 74 f5 68 ?? ?? 40 00 ff d5 eb d3}  //weight: 10, accuracy: Low
        $x_10_3 = {c7 44 24 0c 00 00 00 00 50 ff 15 ?? ?? 40 00 8b 4c 24 18 8b 35 ?? ?? 40 00 6a 00 51 ff d6 6a ff 56 ff 15 ?? ?? 40 00 8d 4c 24 14 e8 ?? ?? ?? ?? 8d 4c 24 18 c7 44 24 0c ff ff ff ff e8}  //weight: 10, accuracy: Low
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_5 = {6f 70 65 6e 00 00 00 00 69 65 78 70 6c 6f 72 65 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_2147800054_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent"
        threat_id = "2147800054"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {84 12 14 00 28 12 14 00 68 74 74 70 3a 2f 2f 67 65 74 79 6f 75 6e 65 65 64 2e 63 6f 6d 2f 72 2e 70 68 70 3f 77 6d 3d 35}  //weight: 1, accuracy: High
        $x_1_2 = {f0 fa 12 00 11 26 40 00 1c fa 12 00 60 fa 12 00 00 00 00 00 00 00 00 00 68 74 74 70 3a 2f 2f 67 65 74 79 6f 75 6e 65 65 64 2e 63 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Agent_2147800054_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent"
        threat_id = "2147800054"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.shadowmp3.com" ascii //weight: 1
        $x_1_2 = "\\NetGuy_Explorer\\Release\\NetGuy_Explorer.pdb" ascii //weight: 1
        $x_1_3 = "Browser Helper Objects\\{CE7C3CF0-25FC-11D1-ABED-784B7D6BE0B3}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_2147800054_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent"
        threat_id = "2147800054"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual C++ Runtime Library" ascii //weight: 1
        $x_1_2 = "winferno.com/c/407/freeze_rpc6bundle_us/REGISTRYFIX" ascii //weight: 1
        $x_1_3 = "rundll32.exe \"%s\",RPCInstall" ascii //weight: 1
        $x_1_4 = "RPCInstall.dll" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_7 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_2147800054_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent"
        threat_id = "2147800054"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual C++ Runtime Library" ascii //weight: 1
        $x_1_2 = "ieopen.yhgames.com/iedown/jdupdate.txt" ascii //weight: 1
        $x_1_3 = "EB383C6E-9912-4850-BCE5-A5A8779D321A" ascii //weight: 1
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services\\" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_6 = "CreateMutexA" ascii //weight: 1
        $x_1_7 = "CreateServiceA" ascii //weight: 1
        $x_1_8 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_2147800054_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent"
        threat_id = "2147800054"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{BD49A3ED-9645-4F06-AC3B-09231CAD748C}" ascii //weight: 1
        $x_1_2 = "xsts.exe" ascii //weight: 1
        $x_1_3 = "dlsts.dll" ascii //weight: 1
        $x_1_4 = "PHacker_C.dll" ascii //weight: 1
        $x_1_5 = "PHacker.ini" ascii //weight: 1
        $x_1_6 = "lec.nevysearch.com" ascii //weight: 1
        $x_1_7 = "update1.upmachines.com" ascii //weight: 1
        $x_1_8 = "CreateDirectoryA" ascii //weight: 1
        $x_1_9 = "DllRegisterServer" ascii //weight: 1
        $x_1_10 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_11 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_2147800054_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent"
        threat_id = "2147800054"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual C++ Runtime Library" ascii //weight: 1
        $x_1_2 = "7428F943-BC4F-4A39-3B43-AB433C523B34" wide //weight: 1
        $x_1_3 = "%s/count.php?id=%i&u=%s&v=%i&t=%i&tm=%i&c=%d&p=%i&ad=%3.3f" wide //weight: 1
        $x_1_4 = "microsoft.com" wide //weight: 1
        $x_1_5 = "omegashippingcorp" wide //weight: 1
        $x_1_6 = "purplesroad" wide //weight: 1
        $x_1_7 = "violetbridge" wide //weight: 1
        $x_1_8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" wide //weight: 1
        $x_1_9 = "DllRegisterServer" ascii //weight: 1
        $x_1_10 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_2147800054_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent"
        threat_id = "2147800054"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "c:\\jdioj.txt" ascii //weight: 1
        $x_1_2 = {ff ff ff ff 08 00 00 00 ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_3 = {ff ff ff ff 07 00 00 00 ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 63 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_2147800054_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent"
        threat_id = "2147800054"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 83 e1 03 f3 a4 bf 0c 52 40 00 83 c9 ff f2 ae f7 d1 2b f9 8b f7 8b d9 8b fa 83 c9 ff f2 ae}  //weight: 1, accuracy: High
        $x_1_2 = "http://keeppure.cn/tool/xxz.exe" ascii //weight: 1
        $x_1_3 = "sysave.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_2147800054_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent"
        threat_id = "2147800054"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "130"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\urlm10n.dll" ascii //weight: 10
        $x_10_2 = "\\urlmon.dll" ascii //weight: 10
        $x_10_3 = "\\index1.dat" ascii //weight: 10
        $x_10_4 = "\\Info1.ini" ascii //weight: 10
        $x_100_5 = "http://www.2828hfdy.com/bak.txt" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_XC_2147800191_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.XC"
        threat_id = "2147800191"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "svchost.exe" ascii //weight: 1
        $x_1_2 = " /qn /x" ascii //weight: 1
        $x_1_3 = "URLUpdateInfo" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Eset\\Nod\\CurrentVersion\\Modules\\AMON\\Settings\\Config000\\Settings" ascii //weight: 1
        $x_1_5 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_6 = "exc_num" ascii //weight: 1
        $x_1_7 = ":_msiexec.exe" ascii //weight: 1
        $x_1_8 = "spersk" ascii //weight: 1
        $x_1_9 = "McShield" ascii //weight: 1
        $x_1_10 = "UninstallString" ascii //weight: 1
        $x_1_11 = "\\Device\\HarddiskVolume1\\" wide //weight: 1
        $x_2_12 = {c9 8b 55 08 33 c0 eb 06 8b ff d3 c9 33 c1 8a 0a 83 c2 01 0a c9 75 f3 c9 c2 04 00}  //weight: 2, accuracy: High
        $x_2_13 = {c9 8b 55 08 33 c0 eb 06 8d 3f d3 c9 33 c1 8a 0a 83 c2 01 0a c9 75 f3 c9 c2 04 00}  //weight: 2, accuracy: High
        $x_2_14 = {c9 ff 75 08 5a 33 c0 eb 06 8d 3f d3 c9 33 c1 8a 0a 83 c2 01 0a c9 75 f3 c9 c2 04 00}  //weight: 2, accuracy: High
        $x_1_15 = "http://alert-ca.com/counter1/fout.php" ascii //weight: 1
        $x_1_16 = "cmd /c t.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_BB_2147800212_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.BB"
        threat_id = "2147800212"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4e 20 6a 00 68 40 42 0f 00 6a 01 51 ff 15 ?? ?? 40 00 6a 00 6a 00 6a 00 6a 00 56 68 ?? ?? 40 00 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 04 6a 00 68 d0 07 00 00 6a 02 8b 48 20 51 ff 15 ?? ?? 40 00 b8 01 00 00 00 c3}  //weight: 1, accuracy: Low
        $x_1_3 = "http://%77%77%77%2E%6B%61%6E%67%6B%2E%63%6E/%74%65%6D%70%2E%68%74%6D%6C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_G_2147800578_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.G"
        threat_id = "2147800578"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3a 2f 2f 77 77 77 2e 62 61 69 64 75 2e 63 6f 6d 00 00 00 00 ff ff ff ff 04 00 00 00 76 31 2e 31 00 00 00 00 68 74 74 70 3a 2f 2f 30 78 64 61 25 32 65 30 78 31 30 25 32 65 30 78 37 38 25 32 65 30 78 66 64 2f 69 65 25 32 65 74 78 74 00 00 00 ff ff ff ff 09 00 00 00 69 65 5f 75 70 2e 65 78 65 00 00 00 ff ff ff ff 2c 00 00 00 68 74 74 70 3a 2f 2f 30 78 64 61 25 32 65 30 78 31 30 25 32 65 30 78 37 38 25 32 65 30 78 66 64 2f 69 65 5f 75 70 25 32 65 65 78 65 00 00 00 00 55 8b ec 33}  //weight: 1, accuracy: High
        $x_1_2 = {3a 2f 2f 77 77 77 2e 62 61 69 64 75 2e 63 6f 6d 00 00 00 00 ff ff ff ff 04 00 00 00 76 31 2e 32 00 00 00 00 ff ff ff ff 19 00 00 00 68 74 74 70 3a 2f 2f 75 75 2e 66 31 32 36 2e 63 6f 6d 2f 69 65 2e 74 78 74 00 00 00 ff ff ff ff 09 00 00 00 69 65 5f 75 70 2e 65 78 65 00 00 00 ff ff ff ff 1c 00 00 00 68 74 74 70 3a 2f 2f 75 75 2e 66 31 32 36 2e 63 6f 6d 2f 69 65 5f 75 70 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = "http://www.91880.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Agent_M_2147800588_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.M"
        threat_id = "2147800588"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 4f 00 00 00 cd 41 66 3d 86 f3 0f 94 c0 0f b6 c0}  //weight: 10, accuracy: High
        $x_10_2 = {64 a1 30 00 00 00 8a 40 02 0f b6 c0}  //weight: 10, accuracy: High
        $x_10_3 = {33 db b9 0a 00 00 00 b8 68 58 4d 56 66 ba 58 56 ed 81 fb 68 58 4d 56 0f 94 c0 0f b6 c0}  //weight: 10, accuracy: High
        $x_1_4 = {80 39 00 56 57 8b c2 74 3b 8b f8 8b f1 2b f9 66 8b 0d ?? ?? ?? ?? 80 0d ?? ?? ?? ?? ff 66 89 0d ?? ?? ?? ?? 8a 0e 80 f1 ?? 66 c7 05 ?? ?? ?? ?? fe ff c6 05 ?? ?? ?? ?? ff 88 0c 37 74 06 46 80 3e 00 75 cb 66 8b 0d ?? ?? ?? ?? 5f 66 f7 d9 66 89 0d ?? ?? ?? ?? 5e 0f be 0d ?? ?? ?? ?? 81 c9 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_5 = {57 50 56 fe c1 6a 01 52 88 0d ?? ?? ?? ?? e8 ?? ?? 00 00 a0 ?? ?? ?? ?? 80 0d ?? ?? ?? ?? ff 00 05 ?? ?? ?? ?? 80 64 37 ff 00 0f be 05 ?? ?? ?? ?? 83 c4 14 0d ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b c6 5f 66 c7 05 ?? ?? ?? ?? fe ff 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_U_2147800590_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.U"
        threat_id = "2147800590"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "RegisterServiceCtrlHandlerA" ascii //weight: 1
        $x_1_2 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_3 = "DisableScriptDebuggerIE" ascii //weight: 1
        $x_1_4 = "SeLoadDriverPrivilege" ascii //weight: 1
        $x_1_5 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_6 = "OpenSCManagerA" ascii //weight: 1
        $x_1_7 = {83 c4 08 8d 8d fc fb ff ff 89 8d ec fb ff ff c7 85 f0 fb ff ff ?? ?? ?? ?? 8b 95 f0 fb ff ff 89 95 f0 fb ff ff c7 85 f4 fb ff ff 00 00 00 00 c7 85 f8 fb ff ff 00 00 00 00 8d 85 ec fb ff ff 50 ff 15 ?? ?? ?? ?? e9 82 01 00 00 68 ?? ?? ?? ?? 6a 01 6a 00 ff 15 ?? ?? ?? ?? 89 85 e0 fb ff ff ff 15 ?? ?? ?? ?? 89 85 e8 fb ff ff 81 bd e8 fb ff ff b7 00 00 00 75 14 8b 8d e0 fb ff ff 51 ff 15 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ZDF_2147800703_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZDF"
        threat_id = "2147800703"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b cb 8b fa 8b d1 be dc b0 40 00 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4}  //weight: 1, accuracy: High
        $x_1_2 = "bho.dll" ascii //weight: 1
        $x_1_3 = "play.dll" ascii //weight: 1
        $x_1_4 = "ser.exe" ascii //weight: 1
        $x_1_5 = "miniup.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_XE_2147800711_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.XE"
        threat_id = "2147800711"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_2 = "CoCreateInstance" ascii //weight: 1
        $x_1_3 = "\\1.exe" ascii //weight: 1
        $x_1_4 = "\\2.exe" ascii //weight: 1
        $x_3_5 = ".exe     " ascii //weight: 3
        $x_3_6 = {55 8b ec b3 00 8b 75 08 ac 84 c0 74 09 3c 20 75 f7 4e 88 1e eb f2 c9 c2 04}  //weight: 3, accuracy: High
        $x_3_7 = {eb 16 8b 55 f8 8b 12 8d 45 f4 50 ff 75 f8 ff 52 38 6a 64}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_P_2147800729_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.P"
        threat_id = "2147800729"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell -inputformat none -outputformat none -NonInteractive -Command" ascii //weight: 2
        $x_2_2 = "Set-MpPreference -DisableRealtimeMonitoring $true" ascii //weight: 2
        $x_2_3 = "-SubmitSamplesConsent NeverSend -MAPSReporting Disabl" ascii //weight: 2
        $x_1_4 = "620c733d900d5.com/" ascii //weight: 1
        $x_1_5 = "addInstall.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_ABC_2147800774_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ABC"
        threat_id = "2147800774"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "164"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {8b 45 f4 33 45 f0 33 f0 3b f7}  //weight: 100, accuracy: High
        $x_10_2 = "raB3G%p" ascii //weight: 10
        $x_10_3 = "status=sleep" ascii //weight: 10
        $x_10_4 = "\\\\.\\pipe\\$%d$" ascii //weight: 10
        $x_10_5 = "InternetConnectA" ascii //weight: 10
        $x_10_6 = "InternetOpenA" ascii //weight: 10
        $x_10_7 = "InternetReadFile" ascii //weight: 10
        $x_1_8 = "ftp://" ascii //weight: 1
        $x_1_9 = "https://" ascii //weight: 1
        $x_1_10 = "http://" ascii //weight: 1
        $x_1_11 = "UrlCookieStr" ascii //weight: 1
        $x_1_12 = "UrlNoLoad" ascii //weight: 1
        $x_1_13 = "B64Decode" ascii //weight: 1
        $x_1_14 = "B64Encode" ascii //weight: 1
        $x_1_15 = "BinToStr" ascii //weight: 1
        $x_1_16 = "Gecko/20070309 Firefox/2.0.0.3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 6 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_ABHL_2147800776_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ABHL"
        threat_id = "2147800776"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\SMS1000Main\\html\\" ascii //weight: 1
        $x_1_2 = "\\SMS1000Update\\HsAc" ascii //weight: 1
        $x_1_3 = ".sms1000.co.kr/App/upapp/" ascii //weight: 1
        $x_1_4 = "ControlNotifier/newagree.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_XF_2147800809_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.XF"
        threat_id = "2147800809"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "svchost.exe" ascii //weight: 1
        $x_1_2 = "ResumeThread" ascii //weight: 1
        $x_1_3 = "VirtualProtectEx" ascii //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_3_5 = {e8 ff ff ff ff c0 5d 89 eb 31 c9 81 e9 77 fe ff ff 83 eb e2 81 73 fb ?? ?? ?? ?? 43 e2 f6}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_XG_2147800810_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.XG"
        threat_id = "2147800810"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 62 6f 74 6e 65 74 ?? 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = "BotNet/0.1 (compatible)" ascii //weight: 1
        $x_1_3 = "/botnet/bho.dll" ascii //weight: 1
        $x_1_4 = "http://67." ascii //weight: 1
        $x_1_5 = "botnet/loader.jsp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Agent_YF_2147800818_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.YF"
        threat_id = "2147800818"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\WINDOWS\\SYSTEM32\\MSService.exe" ascii //weight: 10
        $x_10_2 = "http://df20.dot5hosting.com/~shitshir" ascii //weight: 10
        $x_10_3 = {b8 4f ec c4 4e f7 e9 c1 fa 03 89 c8 c1 f8 1f 29 c2 89 d0 01 c0 01 d0 c1 e0 02 01 d0 01 c0 29 c1 89 c8 0f be 44 28 c8 89 45 a0 eb}  //weight: 10, accuracy: High
        $x_1_4 = "SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" ascii //weight: 1
        $x_1_5 = "MSUpdateSvc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_XH_2147800908_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.XH"
        threat_id = "2147800908"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sload.vbp" wide //weight: 1
        $x_1_2 = "http://sxload.com" wide //weight: 1
        $x_1_3 = "xload.exe" wide //weight: 1
        $x_1_4 = "const.php" wide //weight: 1
        $x_1_5 = "const2.php" wide //weight: 1
        $x_1_6 = "const3.php" wide //weight: 1
        $x_1_7 = "data.php" wide //weight: 1
        $x_1_8 = "search.php" wide //weight: 1
        $x_1_9 = "control.php" wide //weight: 1
        $x_1_10 = "sxload.com" wide //weight: 1
        $x_1_11 = "WINDIR" wide //weight: 1
        $x_1_12 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_13 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\" wide //weight: 1
        $x_1_14 = "about:blank" wide //weight: 1
        $x_1_15 = "?status=main" wide //weight: 1
        $x_1_16 = "?status=const" wide //weight: 1
        $x_1_17 = "?status=search" wide //weight: 1
        $x_1_18 = "?status=imain" wide //weight: 1
        $x_1_19 = "?status=iconst" wide //weight: 1
        $x_1_20 = "?status=isearch" wide //weight: 1
        $x_1_21 = "IWebBrowser2" wide //weight: 1
        $x_1_22 = "?lang=" wide //weight: 1
        $x_1_23 = "/custom?*q=&" wide //weight: 1
        $x_1_24 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_25 = "MSXML2.XMLHTTP" wide //weight: 1
        $x_1_26 = "ADODB.Stream" wide //weight: 1
        $x_1_27 = ".WebBrowser" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (21 of ($x*))
}

rule TrojanDownloader_Win32_Agent_IS_2147800924_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.IS"
        threat_id = "2147800924"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rsvp.exe" ascii //weight: 1
        $x_1_2 = "\\LOCALS~1\\APPLIC~1\\MICROS~1\\" ascii //weight: 1
        $x_1_3 = "CreateMutexA" ascii //weight: 1
        $x_1_4 = "esentutl.exe" ascii //weight: 1
        $x_1_5 = "RegGetKeySecurity" ascii //weight: 1
        $x_1_6 = "cisvc.exe" ascii //weight: 1
        $x_1_7 = "mqtgsvc.exe" ascii //weight: 1
        $x_1_8 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_9 = "ieudinit.exe" ascii //weight: 1
        $x_1_10 = "dllhst3g.exe" ascii //weight: 1
        $x_1_11 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" ascii //weight: 1
        $x_1_12 = "clipsrv.exe" ascii //weight: 1
        $x_1_13 = "sessmgr.exe" ascii //weight: 1
        $x_1_14 = "mstinit.exe" ascii //weight: 1
        $x_1_15 = "comrepl.exe" ascii //weight: 1
        $x_1_16 = "logman.exe" ascii //weight: 1
        $x_1_17 = "cmstp.exe" ascii //weight: 1
        $x_1_18 = "402DA7F3-FFAE-83BE-F133-EA62B44EACA5" ascii //weight: 1
        $x_1_19 = "spoolsv.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_IJ_2147801003_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.IJ"
        threat_id = "2147801003"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "start http://" ascii //weight: 10
        $x_10_2 = "/c echo a > \\System32\\" ascii //weight: 10
        $x_10_3 = "\\cmd.exe /c start \\System32\\winn32t.exe" ascii //weight: 10
        $x_10_4 = "CreateServiceA" ascii //weight: 10
        $x_10_5 = "URLDownloadToFileA" ascii //weight: 10
        $x_1_6 = "bloukasss" ascii //weight: 1
        $x_1_7 = "winzz.exe" ascii //weight: 1
        $x_1_8 = "winn32t.exe" ascii //weight: 1
        $x_1_9 = "81.209.112." ascii //weight: 1
        $x_1_10 = "Blockpornaccess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_ZDG_2147801370_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZDG"
        threat_id = "2147801370"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 61 72 70 70 30 39 33 34 2e 69 65 73 70 61 6e 61 2e 65 73 5c [0-8] 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 01 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 f8 01 1b c0 40 3c 01 75 ?? 6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? ba ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ZDH_2147801371_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZDH"
        threat_id = "2147801371"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 ff 30 64 89 20 68 fa 00 00 00 8d 85 fc fe ff ff 50 e8 ?? ?? ?? ?? 8d 85 f8 fe ff ff 8d 95 fc fe ff ff b9 00 01 00 00 e8 ?? ?? ?? ?? 8b 95 f8 fe ff ff b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 85 f4 fe ff ff 8d 95 fc fe ff ff b9 00 01 00 00 e8 ?? ?? ?? ?? 8b 95 f4 fe ff ff 8d 45 fc b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 fc}  //weight: 1, accuracy: Low
        $x_1_2 = "NtQuerySystemInformation" ascii //weight: 1
        $x_1_3 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_4 = "LuoXue" ascii //weight: 1
        $x_1_5 = "beep.sys" ascii //weight: 1
        $x_1_6 = "sbl.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_AAT_2147801385_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.AAT"
        threat_id = "2147801385"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\cdsss.exe" ascii //weight: 1
        $x_1_2 = "\\vn88.exe" ascii //weight: 1
        $x_1_3 = {2f 6d 69 6d 2f ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65 40 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ABF_2147802619_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ABF"
        threat_id = "2147802619"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {64 a1 00 00 00 00 50 64 89 25 00 00 00 00 51 53 56 8b f1 33 d2 c7 46 18 0f 00 00 00 89 56 14 57 89 74 24 0c 88 56 04 8b 7c 24 20}  //weight: 5, accuracy: High
        $x_5_2 = "bIS0dEpwM2uid3CmdoOsfT5sZXKid2mrbT" ascii //weight: 5
        $x_5_3 = "05122711" ascii //weight: 5
        $x_5_4 = "eYBvAHyt" ascii //weight: 5
        $x_5_5 = "%s\\%s%s.%s" ascii //weight: 5
        $x_1_6 = "newqq\\AdWin" ascii //weight: 1
        $x_1_7 = {43 3a 5c 75 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_ZZD_2147803242_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZZD"
        threat_id = "2147803242"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "%s\\Nt_File_Temp\\%d.tmp" ascii //weight: 10
        $x_10_2 = "%windir%\\Nt_File_Temp\\list.tmp" ascii //weight: 10
        $x_10_3 = "MICK_DOWNLOAD_MUTEX" ascii //weight: 10
        $x_10_4 = "URLDownloadToFileA" ascii //weight: 10
        $x_1_5 = {68 74 74 70 3a 2f 2f 35 31 33 33 38 39 2e 63 6e 2f ?? ?? ?? 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_6 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 6c 61 6e 67 61 2e 6e 65 74 2f ?? ?? ?? 2e 74 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_ACC_2147803349_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ACC"
        threat_id = "2147803349"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_2 = "ShellExecuteA" ascii //weight: 10
        $x_10_3 = "opa! privet!" ascii //weight: 10
        $x_1_4 = "http://countdutycall.info/1/" ascii //weight: 1
        $x_1_5 = {2f 63 20 43 3a 5c 54 45 4d 50 5c ?? ?? ?? ?? 2e 62 61 74 20 22 43 3a 5c 6d 79 61 70 70 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_6 = {40 65 63 68 6f 20 6f 66 66 0d 0a 3a 73 74 61 72 74 0d 0a 65 63 68 6f 20 3e 20 25 31 0d 0a 64 65 6c 20 25 31 0d 0a 69 66 20 65 78 69 73 74 20 25 31 20 67 6f 74 6f 20 73 74 61 72 74 0d 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ACA_2147803350_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ACA"
        threat_id = "2147803350"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "85.17.60." ascii //weight: 10
        $x_10_2 = "vmc_ra_ue" ascii //weight: 10
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_4 = "InternetReadFile" ascii //weight: 1
        $x_1_5 = "HttpSendRequestA" ascii //weight: 1
        $x_1_6 = "StrCmpNIW" ascii //weight: 1
        $x_1_7 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_8 = "CreateProcessA" ascii //weight: 1
        $x_1_9 = "rundll32.exe \"%s\",B" ascii //weight: 1
        $x_1_10 = "LoadAppInit_DLLs" ascii //weight: 1
        $x_1_11 = {70 6f 70 75 70 00}  //weight: 1, accuracy: High
        $x_1_12 = {64 6f 77 6e 6c 6f 61 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ZDE_2147803479_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZDE"
        threat_id = "2147803479"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 6a 00 6a 00 68 a4 2f 41 00 68 a4 2f 41 00 68 a4 2f 41 00 e8 f9 8d ff ff 8d 4d ec}  //weight: 1, accuracy: High
        $x_1_2 = {2f 00 62 00 72 00 2e 00 79 00 6f 00 75 00 74 00 75 00 62 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 77 00 61 00 74 00 63 00 68 00 3f 00 76 00 3d 00 54 00 77 00 35 00 54 00 65 00 6a 00 72 00 53 00 49 00 45 00 41 00 00 00 ff ff ff ff 2c 00 00 00 36 32 46 43 36 32 45 46 30 42 36 36 38 37 38 30 38 33 45 38 30 46 32 46 33 33 39 43 43 33 37 32 39 37 33 31 31 41 34 45 38 43 42 30 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ZDI_2147803482_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZDI"
        threat_id = "2147803482"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 0c 00 00 00 68 ?? ?? ?? ?? 8b 4d 08 8b 51 38 52 e8 ?? ?? ?? ?? 89 ?? ?? ff ff ff c7 ?? ?? ff ff ff 08 00 00 00 8d ?? ?? ff ff ff 8d ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "wyf[1].css" wide //weight: 1
        $x_1_3 = "down" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_WO_2147803772_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.WO"
        threat_id = "2147803772"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&a=1 HTTP/1.1" ascii //weight: 1
        $x_1_2 = "GET /dl?w=" ascii //weight: 1
        $x_1_3 = "Host: 66" ascii //weight: 1
        $x_1_4 = "User-Agent: " ascii //weight: 1
        $x_2_5 = "66.117.37.7" ascii //weight: 2
        $x_2_6 = "/autodetect.exe" ascii //weight: 2
        $x_1_7 = "InternetReadFile" ascii //weight: 1
        $x_1_8 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_9 = "InternetOpenA" ascii //weight: 1
        $x_1_10 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_11 = "GetTempPathA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_WP_2147803773_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.WP"
        threat_id = "2147803773"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 68 65 6c 6c 5f 74 72 61 79 77 6e 64 00 00 00 25 73 5c 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 79}  //weight: 1, accuracy: High
        $x_1_2 = {47 47 00 00 50 50 00 00 6f 70 65 6e 00 00 00 00 46 46 00 00 68 74 74 70 3a 2f 2f 77}  //weight: 1, accuracy: High
        $x_1_3 = {8a 10 8a 1e 8a ca 3a d3 75 1e 84 c9 74 16 8a 50 01 8a 5e 01 8a ca 3a d3 75 0e}  //weight: 1, accuracy: High
        $x_1_4 = {50 ff 73 30 ff 53 10 ff 75 10 ff 53 08 85 c0 0f 94 45 ff 58 74 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Agent_WQ_2147803774_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.WQ"
        threat_id = "2147803774"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_2 = "explorer.exe" ascii //weight: 1
        $x_1_3 = "TerminateProcess" ascii //weight: 1
        $x_1_4 = "OpenProcess" ascii //weight: 1
        $x_1_5 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_6 = "GetTempFileNameA" ascii //weight: 1
        $x_1_7 = "GetTempPathA" ascii //weight: 1
        $x_1_8 = "URLDownloadToCacheFileA" ascii //weight: 1
        $x_1_9 = "\\regcheck" ascii //weight: 1
        $x_2_10 = "/spambot" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_WS_2147803775_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.WS"
        threat_id = "2147803775"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "del %1" ascii //weight: 1
        $x_1_2 = "if exist %1 goto l" ascii //weight: 1
        $x_1_3 = "del %0" ascii //weight: 1
        $x_1_4 = "a.bat" ascii //weight: 1
        $x_1_5 = "file.php?&ID=%s&EXE=" ascii //weight: 1
        $x_1_6 = "IEFrame" ascii //weight: 1
        $x_1_7 = "Shell DocObject View" ascii //weight: 1
        $x_1_8 = "Internet Explorer_Server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanDownloader_Win32_Agent_WU_2147803777_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.WU"
        threat_id = "2147803777"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InternetReadFile" ascii //weight: 1
        $x_1_2 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_3 = "InternetCloseHandle" ascii //weight: 1
        $x_1_4 = "InternetOpenA" ascii //weight: 1
        $x_1_5 = "Mozilla/4.0 (compatible)" ascii //weight: 1
        $x_1_6 = "%s\\%s" ascii //weight: 1
        $x_2_7 = "http://max-stats.com" ascii //weight: 2
        $x_2_8 = "http://sc-cash.com" ascii //weight: 2
        $x_1_9 = "www.teen4-sex.com" ascii //weight: 1
        $x_2_10 = "C:\\WINDOWS\\SYSTEM32\\pref" ascii //weight: 2
        $x_2_11 = "c2.php?i=" ascii //weight: 2
        $x_1_12 = "winlogon32." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_WV_2147803778_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.WV"
        threat_id = "2147803778"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://yupsearch.com" ascii //weight: 3
        $x_1_2 = "/silent_install.exe" ascii //weight: 1
        $x_1_3 = "/sideb.exe" ascii //weight: 1
        $x_1_4 = "\\%ld%d.exe" ascii //weight: 1
        $x_2_5 = "InjectorLoaderMMF" ascii //weight: 2
        $x_2_6 = "WM_HOOKSPY_RK" ascii //weight: 2
        $x_1_7 = "HookProc" ascii //weight: 1
        $x_1_8 = "DownloadRemote" ascii //weight: 1
        $x_1_9 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_10 = "SetWindowsHookExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_WW_2147803779_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.WW"
        threat_id = "2147803779"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://toolbarpartner.com" ascii //weight: 1
        $x_1_2 = "/installed.php?wm=" ascii //weight: 1
        $x_1_3 = "/programs.txt" ascii //weight: 1
        $x_1_4 = "http://sturfajtn.com" ascii //weight: 1
        $x_1_5 = "/w.php" ascii //weight: 1
        $x_1_6 = "/load.txt" ascii //weight: 1
        $x_1_7 = "%WINDIR%\\System32\\$$$" ascii //weight: 1
        $x_1_8 = "regsvr32 /s" ascii //weight: 1
        $x_1_9 = "%SystemRoot%\\sys" ascii //weight: 1
        $x_1_10 = "%i%i.dll" ascii //weight: 1
        $x_1_11 = "%i%i.exe" ascii //weight: 1
        $x_1_12 = "Explorer.exe " ascii //weight: 1
        $x_1_13 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_14 = "%WINDIR%\\System32\\" ascii //weight: 1
        $x_1_15 = "InternetCloseHandle" ascii //weight: 1
        $x_1_16 = "InternetOpenA" ascii //weight: 1
        $x_1_17 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_18 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (16 of ($x*))
}

rule TrojanDownloader_Win32_Agent_WX_2147803780_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.WX"
        threat_id = "2147803780"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Title Windows Update" ascii //weight: 2
        $x_1_2 = "@del %1 >nul" ascii //weight: 1
        $x_1_3 = "@cls" ascii //weight: 1
        $x_1_4 = "@ver" ascii //weight: 1
        $x_1_5 = "@if exist %1 goto d" ascii //weight: 1
        $x_1_6 = "@del %0a.bat C:\\myapp.exe" ascii //weight: 1
        $x_1_7 = "svchost.exe" ascii //weight: 1
        $x_1_8 = "GetModuleFileNameA" ascii //weight: 1
        $x_1_9 = "VirtualProtectEx" ascii //weight: 1
        $x_1_10 = "WriteProcessMemory" ascii //weight: 1
        $x_1_11 = "CreateProcessA" ascii //weight: 1
        $x_1_12 = "WriteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_WY_2147803781_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.WY"
        threat_id = "2147803781"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {60 2b c0 64 8b 40 30 85 c0 78 0c 8b 40 0c 8b 70 1c ad 8b 40 08 eb 09 8b 40 34 8d 40 7c 8b 40 3c 89 44 24 1c 61}  //weight: 3, accuracy: High
        $x_2_2 = {2b ed 8b d3 03 52 3c 8b 52 78 03 d3}  //weight: 2, accuracy: High
        $x_1_3 = "shell_traywnd" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
        $x_1_5 = "CreateRemoteThread" ascii //weight: 1
        $x_1_6 = "DebugActiveProcess" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "GetWindowThreadProcessId" ascii //weight: 1
        $x_1_9 = "OpenProcess" ascii //weight: 1
        $x_1_10 = "ExitProcess" ascii //weight: 1
        $x_1_11 = "GetModuleFileNameA" ascii //weight: 1
        $x_1_12 = "FindWindowA" ascii //weight: 1
        $x_1_13 = "GetCurrentProcessId" ascii //weight: 1
        $x_1_14 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_WZ_2147803785_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.WZ"
        threat_id = "2147803785"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ORIGAMI" ascii //weight: 1
        $x_1_2 = "?self=" ascii //weight: 1
        $x_1_3 = "&type=" ascii //weight: 1
        $x_1_4 = "&key=" ascii //weight: 1
        $x_1_5 = "alive" ascii //weight: 1
        $x_1_6 = "runned" ascii //weight: 1
        $x_10_7 = "TND1http://85.255.119" ascii //weight: 10
        $x_10_8 = "TND2" ascii //weight: 10
        $x_2_9 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\origami" ascii //weight: 2
        $x_2_10 = "BCBC@A" wide //weight: 2
        $x_1_11 = "svchost.exe" ascii //weight: 1
        $x_1_12 = "wininet.dll" ascii //weight: 1
        $x_1_13 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_14 = "InternetGetConnectedState" ascii //weight: 1
        $x_1_15 = "WriteProcessMemory" ascii //weight: 1
        $x_1_16 = "CreateRemoteThread" ascii //weight: 1
        $x_1_17 = "WriteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_XA_2147803786_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.XA"
        threat_id = "2147803786"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "psapi.dll" ascii //weight: 1
        $x_1_2 = "##ws2_32.dll" ascii //weight: 1
        $x_1_3 = "##%d.exe" ascii //weight: 1
        $x_1_4 = "Downloader: fetch OK, %d" ascii //weight: 1
        $x_1_5 = "Downloader: can't open file: %d" ascii //weight: 1
        $x_1_6 = "@@svchost.exe" ascii //weight: 1
        $x_2_7 = "##http://64.27.0.205" ascii //weight: 2
        $x_2_8 = "216.255.189.85" ascii //weight: 2
        $x_2_9 = "w:\\work\\vcprj\\prj\\downloader\\Release\\injdldr.pdb" ascii //weight: 2
        $x_2_10 = "http://64.27.0.205/up/calc2.bin" ascii //weight: 2
        $x_1_11 = "%s\\t%d.exe" ascii //weight: 1
        $x_1_12 = "RSDSk" ascii //weight: 1
        $x_1_13 = "GetLastActivePopup" ascii //weight: 1
        $x_1_14 = ".?AVtype_info@@" ascii //weight: 1
        $x_1_15 = "BC5E6DA8-DD1B-12DD-139A-B5B2378C9A04" ascii //weight: 1
        $x_1_16 = "3645FBCD-ECD2-23D0-BAC4-00DE453DEF6B" ascii //weight: 1
        $x_1_17 = "NSAPI.dll" ascii //weight: 1
        $x_1_18 = "         h((((                  H" wide //weight: 1
        $x_1_19 = "SetThreadContext" ascii //weight: 1
        $x_1_20 = "InternetReadFile" ascii //weight: 1
        $x_1_21 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_22 = "HttpQueryInfoA" ascii //weight: 1
        $x_3_23 = {50 56 56 51 56 89 74 24 44 c7 44 24 48 44 00 00 00 66 c7 44 24 78 05 00 ff 15 34 80 40 00 85 c0}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((18 of ($x_1_*))) or
            ((1 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_2_*) and 12 of ($x_1_*))) or
            ((4 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 15 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_XD_2147803787_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.XD"
        threat_id = "2147803787"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {95 8b 45 3c 8b 44 05 78 8d 74 05 18 ad 91 ad 50 ad 01 e8 92 ad 01 e8}  //weight: 2, accuracy: High
        $x_2_2 = {c1 c2 03 32 10 40 80 38 00 75 f5}  //weight: 2, accuracy: High
        $x_1_3 = "icrosoft\\Active Setup\\Installed" ascii //weight: 1
        $x_1_4 = "msvrhost" ascii //weight: 1
        $x_1_5 = "shell_traywnd" ascii //weight: 1
        $x_1_6 = ".SPIRIT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_ABG_2147803793_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ABG"
        threat_id = "2147803793"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "227"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_100_2 = "shellexecute=RECYCLER\\systems.com" ascii //weight: 100
        $x_10_3 = "open=systems.com" ascii //weight: 10
        $x_10_4 = "shellexecute=systems.com" ascii //weight: 10
        $x_10_5 = "shell\\start\\command=systems.com" ascii //weight: 10
        $x_10_6 = "shell\\read\\command=explorer.exe" ascii //weight: 10
        $x_10_7 = "shell\\start\\command=RECYCLER\\systems.com" ascii //weight: 10
        $x_1_8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_9 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_10 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\system" ascii //weight: 1
        $x_1_11 = "Explorer.exe" ascii //weight: 1
        $x_1_12 = "taskmger.com" ascii //weight: 1
        $x_1_13 = "DisableTaskmgr" ascii //weight: 1
        $x_1_14 = "DisableRegistryTools" ascii //weight: 1
        $x_1_15 = "\\RECYCLER\\systems.com" ascii //weight: 1
        $x_1_16 = "\\system32\\taskmger.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 2 of ($x_10_*) and 7 of ($x_1_*))) or
            ((2 of ($x_100_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_AGA_2147803794_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.AGA"
        threat_id = "2147803794"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "gh0st" ascii //weight: 10
        $x_10_2 = "jsmith@world.com" wide //weight: 10
        $x_10_3 = "\\dllcache\\svchost.exe" ascii //weight: 10
        $x_10_4 = "C:\\TestFiles\\win.ini" ascii //weight: 10
        $x_1_5 = "\\system.bak" ascii //weight: 1
        $x_1_6 = "\\system.log" ascii //weight: 1
        $x_1_7 = "WinExec" ascii //weight: 1
        $x_1_8 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_9 = "GetSystemDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_ADH_2147803797_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ADH"
        threat_id = "2147803797"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".x/txt.txt" ascii //weight: 1
        $x_1_2 = "DownloadEnd" ascii //weight: 1
        $x_1_3 = {52 65 67 69 73 74 65 72 65 64 00 00 00 00 5c 6d 73 68 6e 74 66 79 31 36 2e 64 61 74 00 00 5c 6d 73 68 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_O_2147803803_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.O"
        threat_id = "2147803803"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "occured" ascii //weight: 1
        $x_1_2 = "started" ascii //weight: 1
        $x_1_3 = "ended" ascii //weight: 1
        $x_1_4 = "88-88-88" ascii //weight: 1
        $x_1_5 = "whboy" ascii //weight: 1
        $x_1_6 = "1314" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL" ascii //weight: 1
        $x_1_8 = "%s\\progmon.exe" ascii //weight: 1
        $x_1_9 = "%s\\internt.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule TrojanDownloader_Win32_Agent_ON_2147803812_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ON"
        threat_id = "2147803812"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "URLDownloadToFileA" ascii //weight: 10
        $x_1_2 = "c:\\sss.scr" ascii //weight: 1
        $x_1_3 = "c:\\sss1.scr" ascii //weight: 1
        $x_1_4 = "c:\\sss2.scr" ascii //weight: 1
        $x_1_5 = "http://www.clubnoega.com/_notes/arquivo1.exe" ascii //weight: 1
        $x_1_6 = "http://www.clubnoega.com/_notes/arquivo2.exe" ascii //weight: 1
        $x_1_7 = "http://www.clubnoega.com/_notes/arquivo3.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_OO_2147803813_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.OO"
        threat_id = "2147803813"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c3 68 89 d8 e8 ?? ?? ?? 00 ff 35 ?? ?? ?? 00 8b 1d ?? ?? ?? 00 83 c3 74 89 d8 e8 ?? ?? ?? 00 58 ff 35 ?? ?? ?? 00 8b 1d ?? ?? ?? 00 83 c3 74 89 d8 e8 ?? ?? ?? 00 58 ff 35 ?? ?? ?? 00 8b 1d ?? ?? ?? 00 83 c3 70 89 d8 e8 ?? ?? ?? 00 58 ff 35 ?? ?? ?? 00 8b 1d ?? ?? ?? 00 83 c3 3a}  //weight: 10, accuracy: Low
        $x_1_2 = "ecsdfgalcldlblahchdhbhaxcxdxbxspbpsidibx+si" ascii //weight: 1
        $x_1_3 = "\\|dim nav()WebwRsultoS=CrOjc\"h.ApFUx" wide //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "http://www.ip2location.com/" ascii //weight: 1
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_7 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_8 = "ShellExecuteExA" ascii //weight: 1
        $x_1_9 = "comspec" ascii //weight: 1
        $x_1_10 = "/c del \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_AHF_2147803819_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.AHF"
        threat_id = "2147803819"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%sRundll32.exe \"%s%s\",DllCanUnloadNow" ascii //weight: 1
        $x_1_2 = "RUNDLL32 \"%s\"  Start" ascii //weight: 1
        $x_1_3 = {74 73 70 6f 70 2e 73 79 73 00 74 73 62 68 6f 2e 64 6c 6c 00 74 73 70 6f 70 64 6c 6c 2e 63 61 62 00 74 73 70 6f 70 73 79 73 2e 63 61 62 00 74 73 62 68 6f 2e 63 61 62}  //weight: 1, accuracy: High
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_5 = "SYSTEM\\CurrentControlSet\\Services\\%s" ascii //weight: 1
        $x_1_6 = "dinstnow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_TB_2147803820_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.TB"
        threat_id = "2147803820"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<script DEFER language=javascript>function mf() { return false; }" wide //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3" ascii //weight: 1
        $x_1_3 = "data=%s&key=%s" ascii //weight: 1
        $x_1_4 = "%s|%s|%s|%s|%s|%s|%d|%d|%s" ascii //weight: 1
        $x_1_5 = {3a 52 65 70 65 61 74 20 0a 20 64 65 6c 20 22 25 73 22 20 0a 20 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74}  //weight: 1, accuracy: High
        $x_10_6 = "Wininet.dll" ascii //weight: 10
        $x_1_7 = "_self" ascii //weight: 1
        $x_1_8 = "Updater %s - %s" ascii //weight: 1
        $x_10_9 = "Internet Explorer" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_AAA_2147803827_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.AAA"
        threat_id = "2147803827"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ec 10 8d 44 24 04 50 68 1f 00 02 00 6a 00 68 ?? ?? 41 00 68 01 00 00 80 c7 44 24 14 00 00 00 00 ff 15 ?? ?? 41 00 85 c0 74 06 32 c0 83 c4 10 c3}  //weight: 10, accuracy: Low
        $x_10_2 = {2f 47 6f 6f 67 6c 65 5f 66 69 6c 65 73 2f 68 70 ?? 2e 67 69 66}  //weight: 10, accuracy: Low
        $x_10_3 = "Software\\Microsoft\\new WWW\\vars" ascii //weight: 10
        $x_10_4 = "Software\\Microsoft\\WebServer Data" ascii //weight: 10
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_ADG_2147803830_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ADG"
        threat_id = "2147803830"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "98"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "/C net view >c:\\nv" ascii //weight: 50
        $x_10_2 = ":ExeDelete" ascii //weight: 10
        $x_10_3 = "del %ExePath%" ascii //weight: 10
        $x_10_4 = "if exist %ExePath% goto ExeDelete" ascii //weight: 10
        $x_10_5 = "del %BatPath%" ascii //weight: 10
        $x_5_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 5
        $x_1_7 = "ShellExecuteA" ascii //weight: 1
        $x_1_8 = "FtpOpenFileA" ascii //weight: 1
        $x_1_9 = "InternetWriteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_BCB_2147803831_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.BCB"
        threat_id = "2147803831"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://g1.globo.com/Noticias/SaoPaulo/0,,MUL73439-5605,00.html" ascii //weight: 10
        $x_10_2 = "c:\\winupdte.exe" ascii //weight: 10
        $x_10_3 = "http://globonoticia.iitalia.com/noticia.com" ascii //weight: 10
        $x_5_4 = "ShellExecuteA" ascii //weight: 5
        $x_5_5 = "URLDownloadToFileA" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_BCF_2147803832_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.BCF"
        threat_id = "2147803832"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {22 20 67 6f 74 6f 20 52 65 70 65 61 74 0a 64 65 6c 20 22 00 22 0a 69 66 20 65 78 69 73 74 20 22 00 00 00 00 3a 52 65 70 65 61 74 0a 64 65 6c 20 22 00 00 00 63 3a 5c 74 65 6d 70 2e 62 61 74}  //weight: 10, accuracy: High
        $x_10_2 = "\\ucleaner_setup.exe" ascii //weight: 10
        $x_10_3 = "\\s2f.exe" ascii //weight: 10
        $x_2_4 = "URLDownloadToFileA" ascii //weight: 2
        $x_1_5 = "\\Casino.ico" ascii //weight: 1
        $x_1_6 = "\\Spyware Remover.ico" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_BCK_2147803835_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.BCK"
        threat_id = "2147803835"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 8c 24 30 01 00 00 8b 9c 24 2c 01 00 00 8b e9 8b d0 33 c0 8b fb c1 e9 02 f3 ab 8b cd 89 54 24 10 83 e1 03 83 fa 01 f3 aa 74 0e 83 fa 02 74 09 8b bc 24 28 01 00 00 eb 75 8b 56 04 8d 44 24 14 50 68 19 00 02 00 8d 4e 0c 6a 00 51 52 ff 15}  //weight: 10, accuracy: High
        $x_10_2 = {68 74 74 70 3a 2f 2f [0-32] 2f 70 72 6f 67 72 61 6d 2f [0-832] 53 65 74 75 70 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_1_3 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_MU_2147803836_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.MU"
        threat_id = "2147803836"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://nemesis.feed.parkingspa.com/Nemesis" ascii //weight: 1
        $x_1_2 = "C:\\Program Files\\DomainSpa\\Nemesis\\Client\\NemesisClient.exe" ascii //weight: 1
        $x_1_3 = "StartServiceA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ZAI_2147803840_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZAI"
        threat_id = "2147803840"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {00 6f 75 68 20 62 61 62}  //weight: 3, accuracy: High
        $x_1_2 = "%s\\%s.exe" ascii //weight: 1
        $x_3_3 = "%s\\regsvr32.exe \"%s\" %s" ascii //weight: 3
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_3_5 = ".co.kr/" ascii //weight: 3
        $x_1_6 = "C:\\WINDOWS\\SYSTEM32\\*.*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_ZAL_2147803849_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZAL"
        threat_id = "2147803849"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {6e 6f 74 65 70 6f 64 2e 65 78 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 72 73 76 70 2e 65 78 65}  //weight: 3, accuracy: High
        $x_2_2 = "\"C:\\WINDOWS\\SYSTEM32\\notepod.exe\" \"%1\"" ascii //weight: 2
        $x_2_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.txt" ascii //weight: 2
        $x_2_4 = "{990B770D-62AE-5421-DA6D-16033B76258C}" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_ZBC_2147803850_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZBC"
        threat_id = "2147803850"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.jesuser.cn/plug/doSelect.asp?CMD=%s" ascii //weight: 1
        $x_1_2 = {ff ff ff ff 0c 00 00 00 67 65 74 72 61 6e 64 74 69 6d 65 7c 00 00 00 00 ff ff ff ff 2c 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 71 71 68 75 64 6f 6e 67 2e 63 6e 2f 75 73 65 72 73 65 74 75 70 2e 61 73 70 3f 61 63 74 69 6f 6e 3d 00 00 00 00 ff ff ff ff 12 00 00 00 73 65 74 75 70 7c 25 73}  //weight: 1, accuracy: High
        $x_1_3 = {5c 73 76 2f 2f 63 68 2f 2f 6f 73 74 2f 2f 2e 65 2f 2f 78 65 2f 2f 00 00 ff ff ff ff 06 00 00 00 63 6f 6d 6d 6f 6e 00 00 ff ff ff ff 04 00 00 00 65 78 65 63 00 00 00 00 ff ff ff ff 02 00 00 00 5c 5c 00 00 ff ff ff ff 08 00 00 00 77 5c 5c 64 6c 5c 5c 6c 00 00 00 00 ff ff ff ff 07 00 00 00 54 58 54 46 49 4c 45 00 ff ff ff ff 0c 00 00 00 45 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 ff ff ff ff 05 00 00 00 6e 65 78 65 63 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ZBC_2147803850_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZBC"
        threat_id = "2147803850"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 73 65 61 72 63 68 3f 63 6c 69 65 6e 74 3d 00 26 63 68 61 6e 6e 65 6c 3d 00 00 00 26 69 65 3d 47 42 32 33 31 32 26 6f 65 3d 47 42 32 33 31 32 26 68 6c 3d 7a 68 2d 43 4e 26 71 3d 00 00 00 00 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6e}  //weight: 1, accuracy: High
        $x_1_2 = {2f 73 65 61 72 63 68 3f 71 3d 00 00 26 63 6c 69 65 6e 74 3d 00 00 00 00 26 69 65 3d 67 62 26 6f 65 3d 55 54 46 2d 38 26 68 6c 3d 7a 68 2d 43 4e 26 63 68 61 6e 6e 65 6c 3d 00 00 00 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6e}  //weight: 1, accuracy: High
        $x_1_3 = {26 65 69 3d 00 00 00 00 26 63 74 3d 25 73 26 63 64 3d 25 73 00 00 00 00 72 65 74 75 72 6e 20 63 6c 6b 00 00 2f 75 72 6c 3f 73 61 3d 00 00 00 00 25 73 25 73 26 65 69 3d 25 73 00 00 68 72 65 66 3d}  //weight: 1, accuracy: High
        $x_1_4 = {66 74 70 3a 2f 2f 67 67 73 73 3a 78 73 77 32 78 73 77 32 40 67 ?? 2e 61 64 66 69 72 65 66 6f 78 2e 63 6e 2f 67 ?? 2f 67 63 6f 6e 2e 64 61 74 00 66 74 70 3a 2f 2f 67 67 73 73 3a 78 73 77 32 78 73 77 32 40 67 ?? 2e 61 64 66 69 72 65 66 6f 78 2e 63 6e 2f 67 ?? 2f 67 6b 65 79 2e 64 61 74}  //weight: 1, accuracy: Low
        $x_1_5 = {67 63 6f 6e 2e 64 61 74 00 00 00 00 67 6b 65 79 2e 64 61 74 00 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 41 42 5c 45 78 70 6f 72 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Agent_ZH_2147803853_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZH"
        threat_id = "2147803853"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "149"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {25 73 3d 25 73 0d 0a 00 4e 55 4c 00}  //weight: 100, accuracy: High
        $x_5_2 = "[rename]" ascii //weight: 5
        $x_5_3 = "wininit." ascii //weight: 5
        $x_5_4 = "\\usrinit.dll" ascii //weight: 5
        $x_5_5 = "{5B02EBA1-EFDD-477D-A37F-05383165C9C0}" ascii //weight: 5
        $x_5_6 = "ZwOpenSection" ascii //weight: 5
        $x_5_7 = "InternetReadFile" ascii //weight: 5
        $x_5_8 = "ShellExecuteA" ascii //weight: 5
        $x_5_9 = "MapViewOfFile" ascii //weight: 5
        $x_5_10 = "regsvr32" ascii //weight: 5
        $x_2_11 = "http://www.alxup.com/bin/Up.ini" ascii //weight: 2
        $x_1_12 = "\\UpAuto.ini" ascii //weight: 1
        $x_1_13 = "AutoUp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ACB_2147803858_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ACB"
        threat_id = "2147803858"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CoMarshalInterThreadInterfaceInStream" ascii //weight: 10
        $x_10_2 = "InternetOpenUrlA" ascii //weight: 10
        $x_10_3 = "%s?cmp=%s&uid=%s&guid=%s&affid=%s&nid=ad&lid=%s" ascii //weight: 10
        $x_1_4 = "http://65.243.103." ascii //weight: 1
        $x_1_5 = "http://89.188.16." ascii //weight: 1
        $x_1_6 = "MJUAN" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\MS Juan" ascii //weight: 1
        $x_1_8 = "Juan_Tracking_Mutex" wide //weight: 1
        $x_1_9 = "Mutex_Juan_LC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_ACZ_2147803860_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ACZ"
        threat_id = "2147803860"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 04 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 ff 15 00 10 40 00 a3 fc 23 40 00 ff 15 08 10 40 00 a3 f8 23 40 00 8d 35 00 20 40 00 c7 06 02 00 01 00 56 ff 35 fc 23 40 00 ff 15 10 10 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {56 53 57 33 d2 b9 20 00 00 00 ff 35 c4 23 40 00 58 ff 35 c8 23 40 00 5b f7 f1 c1 e0 02 03 d8 8b 3d e0 23 40 00 57 33 c0 4f 8b 33 0f ce 8a ca d3 e6 c1 ee 1f 85 f6 74 06 8b cf d3 e6 03 c6 42 83 fa 20 75 05 83 c3 04 33 d2 85 ff 75 db 59 01 0d c4 23 40 00 5f 5b 5e c3}  //weight: 1, accuracy: High
        $x_1_3 = {c9 c3 53 8b 1d ?? ?? ?? ?? 33 c9 b5 01 88 2b 88 4b 01 81 c3 a0 00 00 00 fe c1 75 f1 89 0d}  //weight: 1, accuracy: Low
        $x_1_4 = {55 8b ec 33 c0 50 50 50 ff 75 08 50 50 ff 15 00 10 40 00}  //weight: 1, accuracy: High
        $x_1_5 = {16 00 00 00 00 00 00 48 00 43 72 65 61 74 65 54 68 72 65 61 64 00 00 75 00 45 78 69 74 50 72 6f 63 65 73 73 00 e5 00 47 65 74 43 75 72 72 65 6e 74 54 68 72 65 61 64 00 00 29 01 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 00 52 01 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ADD_2147803862_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ADD"
        threat_id = "2147803862"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{3F6D54BB-34EE-4469-B094-86B09E53BCF8}" ascii //weight: 1
        $x_1_2 = "C:\\WINDOWS\\SYSTEM32\\comm.xml" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer" ascii //weight: 1
        $x_1_4 = {68 75 6d 61 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = "comm.php" ascii //weight: 1
        $x_1_6 = "newuser.php" ascii //weight: 1
        $x_1_7 = "InternetOpenA" ascii //weight: 1
        $x_1_8 = "Down.dll" ascii //weight: 1
        $x_1_9 = "sploso.com" ascii //weight: 1
        $x_1_10 = "hellExecuteA" ascii //weight: 1
        $x_1_11 = "reateProcessA" ascii //weight: 1
        $x_1_12 = {75 73 65 72 69 64 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_13 = "\\file.exe" ascii //weight: 1
        $x_1_14 = {50 c6 00 43 8b 45 fc 50 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_BCH_2147803866_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.BCH"
        threat_id = "2147803866"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://www.comegoto.com/host.jpg" ascii //weight: 10
        $x_5_2 = "URLDownloadToFileA" ascii //weight: 5
        $x_1_3 = {4d 41 49 4e 5f 53 54 41 52 54 00}  //weight: 1, accuracy: High
        $x_1_4 = "delme.bat" ascii //weight: 1
        $x_1_5 = "SETTINGS" wide //weight: 1
        $x_1_6 = "del %s" ascii //weight: 1
        $x_1_7 = "if exist \"%s\" goto try" ascii //weight: 1
        $x_1_8 = "del \"%s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_BCH_2147803866_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.BCH"
        threat_id = "2147803866"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://www.comegoto.com/host.jpg" ascii //weight: 10
        $x_5_2 = "URLDownloadToFileA" ascii //weight: 5
        $x_1_3 = {4d 61 69 6e 5f 53 74 61 72 74 5f 51 00}  //weight: 1, accuracy: High
        $x_1_4 = "nonome.bat" ascii //weight: 1
        $x_1_5 = {4d 00 41 00 4b 00 45 00 52 00 45 00 53 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "del %s" ascii //weight: 1
        $x_1_7 = "if exist \"%s\" goto try" ascii //weight: 1
        $x_1_8 = "del \"%s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_AUV_2147803868_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.AUV"
        threat_id = "2147803868"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://dist.checkin100.com/command?projectID=%s&affiliateID=%s&campaignID=%s&application=%s&v=9" ascii //weight: 1
        $x_1_2 = "http://sense-super.com/cgi/execute_log.cgi?filename=debug&type=failed_registry_read" ascii //weight: 1
        $x_1_3 = "http://client.myadultexplorer.com/bundle_report.cgi?v=10&campaignID=%s&message=%s" ascii //weight: 1
        $x_1_4 = "%s\\test_file1234.txt" ascii //weight: 1
        $x_1_5 = "Software\\LifeTimePorn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_AVZ_2147803869_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.AVZ"
        threat_id = "2147803869"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_2 = "\"%s\" /VERYSILENT" ascii //weight: 1
        $x_1_3 = "/REGISTRYFIX.EXE" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_5 = "c:\\RPCInstall\\Release\\RPCInstall.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_DO_2147803873_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.DO"
        threat_id = "2147803873"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CLSID = s '{ABCDECF0-4B15-11D1-ABED-709549C10000}'" ascii //weight: 1
        $x_1_2 = "/search.php?q=%s&adv=%d&id=%d&s=%d" ascii //weight: 1
        $x_1_3 = "10trustedsites.com" ascii //weight: 1
        $x_1_4 = "top10searches.net" ascii //weight: 1
        $x_1_5 = "top20searches.net" ascii //weight: 1
        $x_1_6 = "IEHelper" wide //weight: 1
        $x_1_7 = "Content-Type: text/html; charset=UTF-8" ascii //weight: 1
        $x_1_8 = "search.msn.com/results.aspx" ascii //weight: 1
        $x_1_9 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_DV_2147803874_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.DV!dll"
        threat_id = "2147803874"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LookupPrivilegeValueA" ascii //weight: 1
        $x_1_2 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_3 = "OpenProcessToken" ascii //weight: 1
        $x_1_4 = "ShellExecuteA" ascii //weight: 1
        $x_1_5 = "GlobalFindAtomA" ascii //weight: 1
        $x_1_6 = "ssppoooollssvv" ascii //weight: 1
        $x_1_7 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_8 = "360tray.exe" ascii //weight: 1
        $x_1_9 = "360Safe.exe" ascii //weight: 1
        $x_1_10 = "antiarp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_EF_2147803875_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.EF"
        threat_id = "2147803875"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\svchost.dll" ascii //weight: 1
        $x_1_2 = "Global\\IPRIP" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 1
        $x_1_4 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" ascii //weight: 1
        $x_1_5 = "SYSTEM\\CurrentControlSet\\Services\\IPRIP" ascii //weight: 1
        $x_1_6 = "cmd.exe /c net start %s & del \"%s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_EF_2147803876_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.EF!dll"
        threat_id = "2147803876"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ServiceMain" ascii //weight: 1
        $x_1_2 = "Global\\IPRIP" ascii //weight: 1
        $x_1_3 = "Applications\\iexplore.exe\\shell\\open\\command" ascii //weight: 1
        $x_1_4 = "\\svchost.dll" ascii //weight: 1
        $x_1_5 = "SYSTEM\\CurrentControlSet\\Services\\" ascii //weight: 1
        $x_1_6 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_7 = "CVideoCap" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_AJI_2147803880_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.AJI"
        threat_id = "2147803880"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\." ascii //weight: 1
        $x_1_2 = "/msword/search/" ascii //weight: 1
        $x_1_3 = "/exel/download/" ascii //weight: 1
        $x_1_4 = "/window/stop/" ascii //weight: 1
        $x_1_5 = "/pascal/find/" ascii //weight: 1
        $x_1_6 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_7 = "/xp/run/" ascii //weight: 1
        $x_1_8 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_9 = "InternetReadFile" ascii //weight: 1
        $x_1_10 = "ShellExecuteExA" ascii //weight: 1
        $x_1_11 = {56 42 53 63 72 69 70 74 00 3d 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: High
        $x_1_12 = "&restart=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_EO_2147803881_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.EO"
        threat_id = "2147803881"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 01 75 20 8d 85 cc f7 ff ff 50 ff 15 ?? ?? ?? ?? 8d 85 cc fb ff ff 6a 00 50 ff 15 ?? ?? ?? ?? b3 01 eb 02}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f [0-48] 2f 6b 69 6c 6c 73 2e 74 78 74 3f 74 69 6d 65 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_IW_2147803882_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.IW"
        threat_id = "2147803882"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 64 2e 25 64 2e 25 64 2e 25 64 00 3f 64 61 74 61 3d}  //weight: 1, accuracy: High
        $x_1_2 = "Msxml2.DOMDocument" ascii //weight: 1
        $x_1_3 = "Somefox" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f [0-32] 2f 73 69 7a 65 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_5 = "SnmpExtensionTrap" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "if exist \"" ascii //weight: 1
        $x_1_8 = "\" > nul 2> nul" ascii //weight: 1
        $x_1_9 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Mozilla\\Somefox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_JF_2147803884_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.JF"
        threat_id = "2147803884"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 68 71 73 65 78 74 75 62 65 30 38 2e 63 6f 6d 2f 67 65 74 73 6f 66 74 2f 74 61 73 6b 2e 70 68 70 3f 76 3d [0-16] 26 71 3d}  //weight: 1, accuracy: Low
        $x_1_3 = "\\Adobe\\Manager.exe" ascii //weight: 1
        $x_1_4 = "\\crc.dat" ascii //weight: 1
        $x_1_5 = "kiwibot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ZK_2147803892_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZK"
        threat_id = "2147803892"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ie6PatchBar.exe" ascii //weight: 1
        $x_1_2 = "Kb83830597TmpNew.exe" ascii //weight: 1
        $x_1_3 = "down1.exe" ascii //weight: 1
        $x_1_4 = "KVXP_Monitor" ascii //weight: 1
        $x_1_5 = "Custom_IeStartFlag" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Setup\\{250D8FBA-AD11-11D023-98A823-08002423102}" ascii //weight: 1
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" ascii //weight: 1
        $x_1_9 = "Windows Explorer Patch" ascii //weight: 1
        $x_1_10 = "AppEvent.exe" ascii //weight: 1
        $x_1_11 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_AQ_2147803893_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.gen!AQ"
        threat_id = "2147803893"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {52 45 53 53 44 54 2e 65 78 65 00 73 79 73 00 5c 52 45 53 53 44 54 2e 73 79 73 00 5c 73 79 73 61 76 65 2e 65 78 65}  //weight: 10, accuracy: High
        $x_10_2 = "cmd.exe /c echo ping 127.1 -n 4 >nul 2>nul >\"C:\\Program Files\\sys.bat\" &  echo del" ascii //weight: 10
        $x_10_3 = "cmd.exe /c net stop wscsvc&net stop sharedaccess&sc config sharedaccess start= disabled&sc config wscsvc start= disabled" ascii //weight: 10
        $x_10_4 = "stop McShield&net stop \"Norton AntiVirus Server" ascii //weight: 10
        $x_1_5 = "remotecontrol" ascii //weight: 1
        $x_1_6 = "C:\\Program Files\\Rising\\AntiSpyware\\ieprot.dll" ascii //weight: 1
        $x_1_7 = "birdluck6.cn/root/sysupdate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_ZT_2147803895_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZT"
        threat_id = "2147803895"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 4c 24 18 51 68 00 10 00 00 56 56 57 ff 15 ?? ?? ?? ?? 81 c3 00 10 00 00 81 c6 00 10 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {68 04 01 00 00 51 56 55 e8 ?? ?? ?? ?? 85 c0 75 ?? 55 68 80 00 00 00 6a 03 55 6a 01 8d 94 24 2c 01 00 00 68 00 00 00 80 52 ff 15}  //weight: 10, accuracy: Low
        $x_5_3 = "http://wmjqr.cn" ascii //weight: 5
        $x_1_4 = "KernelFailCheck" ascii //weight: 1
        $x_1_5 = "%s\\syscheck.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_QP_2147803899_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.QP"
        threat_id = "2147803899"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Internet Explorer\\IEXPLORE.EXE\" http://www.178gg.com/lianjie/" ascii //weight: 2
        $x_2_2 = {49 6e 74 6f 72 6e 6f 74 [0-8] 45 78 70 6c 6f 72 6f 72 [0-8] 2e 6c 6e 6b}  //weight: 2, accuracy: Low
        $x_1_3 = "\\fresh.exe" ascii //weight: 1
        $x_1_4 = "taourl.com" ascii //weight: 1
        $x_1_5 = "download_quiet" ascii //weight: 1
        $x_1_6 = {70 69 70 69 5f 64 61 65 5f [0-4] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_ABHJ_2147803918_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ABHJ"
        threat_id = "2147803918"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sc.exe start " ascii //weight: 1
        $x_1_2 = "del %0" ascii //weight: 1
        $x_1_3 = "IEFrame" ascii //weight: 1
        $x_1_4 = "\\Device\\PhysicalMemory" wide //weight: 1
        $x_1_5 = "\\WINDOWS\\system32\\regsvr32.exe" ascii //weight: 1
        $x_1_6 = "58.49.58.20" ascii //weight: 1
        $x_1_7 = "sc.exe description " ascii //weight: 1
        $x_1_8 = "\\WINDOWS\\sc.exe" ascii //weight: 1
        $x_1_9 = "stoped" ascii //weight: 1
        $x_1_10 = " -dbat\" type= own type= interact start= auto DisplayName= " ascii //weight: 1
        $x_1_11 = "sc.exe create " ascii //weight: 1
        $x_1_12 = "CWebBrowser2" ascii //weight: 1
        $x_1_13 = "GetSecurityInfo" ascii //weight: 1
        $x_1_14 = "Internet Explorer_TridentDlgFrame" ascii //weight: 1
        $x_1_15 = "' target='_blank'>test</a>" ascii //weight: 1
        $x_1_16 = "C:\\bootfont.biz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_KA_2147803925_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.KA"
        threat_id = "2147803925"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual C++ Runtime Library" ascii //weight: 1
        $x_1_2 = "vrsOkInt.php" ascii //weight: 1
        $x_1_3 = "okinternet.co.kr" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_6 = "HttpOpenRequestA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_AAC_2147803927_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.AAC"
        threat_id = "2147803927"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "system32\\drivers\\pcihdd.sys" ascii //weight: 1
        $x_1_2 = "System32\\Userinit.exe" ascii //weight: 1
        $x_1_3 = ".mackt" ascii //weight: 1
        $x_1_4 = "OpenSCManagerA" ascii //weight: 1
        $x_1_5 = "CreateServiceA" ascii //weight: 1
        $x_1_6 = "DeleteService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ZN_2147803928_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZN"
        threat_id = "2147803928"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "105"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {7b 33 34 46 36 37 33 45 ?? 2d 38 37 38 46 2d 31 31 44 35 2d 42 39 38 41 2d 41 30 42 30 44 30 37 42 38 43 37 43 7d}  //weight: 100, accuracy: Low
        $x_1_2 = "Internet Explorer_Server" ascii //weight: 1
        $x_1_3 = "HWND :%ld" ascii //weight: 1
        $x_1_4 = "http://www.myfiledistribution.com/mfd.php" ascii //weight: 1
        $x_1_5 = "IELite ver:0.0.0" ascii //weight: 1
        $x_2_6 = {a1 54 b1 00 10 8b 0d 58 b1 00 10 66 8b 15 5c b1 00 10 89 84 24 50 01 00 00 89 8c 24 54 01 00 00 b9 3e 00 00 00 33 c0 8d bc 24 5a 01 00 00 66 89 94 24 58 01 00 00 be bc b1 00 10 f3 ab 66 ab b9 0a 00 00 00 8d bc 24 ec 00 00 00 f3 a5 66 a5 b9 0e 00 00 00 33 c0 8d bc 24 16 01 00 00 f3 ab 66 ab e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_ACE_2147803931_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ACE"
        threat_id = "2147803931"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "82"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "st1.serveblog.net" ascii //weight: 1
        $x_1_2 = "yllapa.no-ip.info" ascii //weight: 1
        $x_1_3 = "az8.no-ip.info" ascii //weight: 1
        $x_1_4 = "{5E3CD02D-23F7-F6A5-D0BA-5D96D23FD152}" ascii //weight: 1
        $x_1_5 = "{A064C35E-29AC-30E1-1C19-9D8FF1A15C19}" ascii //weight: 1
        $x_1_6 = "{AC3FD4AE-6460-A889-B5BA-61FBA9330853}" ascii //weight: 1
        $x_10_7 = "CONNECT %s:%i HTTP/1.0" ascii //weight: 10
        $x_10_8 = "SOFTWARE\\Classes\\http\\shell\\open\\command" ascii //weight: 10
        $x_10_9 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_10 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 10
        $x_10_11 = "Software\\Microsoft\\Active Setup\\Installed Components" ascii //weight: 10
        $x_10_12 = "advpack" ascii //weight: 10
        $x_10_13 = "StubPath" ascii //weight: 10
        $x_10_14 = {8b ec 81 c4 3c f2 ff ff 60 33 c0 8d bd 90 f2 ff ff b9 5b 0d 00 00 f3 aa 33 c0 8d bd 4c f2 ff ff b9 44 00 00 00 f3 aa c7 85 b9 f3 ff ff e6 00 00 00 e9 a6 13 00 00 55 8b ec 83 c4 d0 8b 75 08 68 11 27 34 06 ff b6 bb 0a 00 00 ff b6 e1 00 00 00 ff 96 dd 00 00 00 ff d0 89 86 bd 08 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_FY_2147803934_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.FY"
        threat_id = "2147803934"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sc.exe start" ascii //weight: 1
        $x_1_2 = "\\WINDOWS\\system32\\regsvr32.exe" ascii //weight: 1
        $x_1_3 = "\\drivers\\" ascii //weight: 1
        $x_1_4 = "AMDcore2" ascii //weight: 1
        $x_10_5 = "58.49.58.20" ascii //weight: 10
        $x_10_6 = {89 90 68 d4 00 00 89 90 6c d4 00 00 88 90 20 28 01 00 89 90 38 28 01 00 89 90 3c 28 01 00 89 90 40 28 01 00 89 90 34 28 01 00 89 90 44 28 01 00 c7 80 48 28 01 00 80 00 00 00 89 90 4c 28 01 00 89 90 50 28 01 00}  //weight: 10, accuracy: High
        $x_10_7 = {8d 85 fc f7 ff ff 68 ?? ?? 40 00 50 e8 ?? ?? 00 00 8d 85 fc f7 ff ff 56 50 e8 ?? ?? 00 00 8d 85 fc f7 ff ff 68 ?? ?? 40 00 50 e8 ?? ?? 00 00 8d 85 fc ef ff ff 50 8d 85 fc f7 ff ff 50 e8 ?? ?? 00 00 8d 85 fc f7 ff ff 68 ?? ?? 40 00 50}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_ID_2147803935_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ID"
        threat_id = "2147803935"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 6d 6f 6b 31 32 33 [0-21] 2e 63 6f 6d 2f 6b 69 6c 6c 73 2e 74 78 74 3f 74}  //weight: 1, accuracy: Low
        $x_1_2 = {62 61 69 64 75 61 73 70 [0-21] 2e 63 6f 6d 2f 6b 69 6c 6c 73 2e 74 78 74 3f 74}  //weight: 1, accuracy: Low
        $x_1_3 = "122.224.9.151/kills.txt?t" ascii //weight: 1
        $x_10_4 = {6a 04 99 59 f7 f9 8d 85 ?? ?? ff ff 68 fc 03 00 00 50 8b f2 ff 15 ?? ?? 40 00}  //weight: 10, accuracy: Low
        $x_10_5 = {59 84 c0 59 75 23 68 d0 07 00 00 ff 15 ?? ?? 40 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_CBN_2147803938_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.CBN"
        threat_id = "2147803938"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FindFirstUrlCacheEntry" ascii //weight: 1
        $x_1_2 = "Content-Type: application/x-www-form-urlencoded" wide //weight: 1
        $x_1_3 = "InternetExplorer.Application" wide //weight: 1
        $x_1_4 = "<script DEFER language=javascript>" wide //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones" ascii //weight: 1
        $x_8_6 = {74 65 78 74 2f 68 74 6d 00 00 00 00 2a 2e 2a 00 5c 2a 2e 2a 00 00 00 00 4b 57 20 41 6e 61 6c 79 73 65 72 3a 20 74 6f 70 20 67 72 6f 75 70 3d 25 73 20 72 61 74 69 6e 67 3d 25 64 00 4b 57 20 41 6e 61 6c 79 73 65 72 3a 20 69 64 3d 25 73 20 20 72 61 74 69 6e 67 3d 25 64 20 28 74 6f 70 6b 77 3d 25 73 29 00 00 00 00 72 62 00 00 25 35 64 25 35 64 00 00 25 35 64 00 77 62 00 00 25 73 5c 25 73 00 00 00}  //weight: 8, accuracy: High
        $x_8_7 = {50 52 4f 58 59 00 00 00 4d 4f 44 45 4d 00 00 00 4c 41 4e 00 4e 41 00 00 25 64 2a 25 64 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 00 00 00 00 56 65 72 73 69 6f 6e 00 53 6f 66 74 77 61 72 65 5c 4d 6f 7a 69 6c 6c 61 5c 4d 6f 7a 69 6c 6c 61 20 46 69 72 65 66 6f 78 00 00 00 00 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 00 00 2d 31 00 00 43 3a 5c 00 43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 49 6e 74 65 72 6e 61 74 69 6f 6e 61 6c 00 4c 6f 63 61 6c 65 00 00}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ZAN_2147803942_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZAN"
        threat_id = "2147803942"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c6 44 30 05 0a 8d 45 ?? 6a 00 50 8b 03 ff 75 10 51 ff 34 30 ff 15 ?? ?? ?? ?? 85 c0 75 ?? ff 15 ?? ?? ?? ?? 6a 05 59 3b c1 75 ?? c7 05 ?? ?? ?? ?? 09 00 00 00 89 0d ?? ?? ?? ?? e9 ?? ?? 00 00 83 f8 6d}  //weight: 10, accuracy: Low
        $x_10_2 = {f3 ab 66 ab aa 8d 45 f0 c6 45 fc 03 50 68 19 00 02 00 53 c7 45 e8 00 04 00 00 ff 75 14 68 02 00 00 80 ff 15 ?? ?? ?? ?? 85 c0 75 ?? 8d 45 ?? 50 8d 85 ?? ?? ff ff 50 53 53}  //weight: 10, accuracy: Low
        $x_10_3 = {83 c4 10 8d 45 ?? 50 8d 45 ?? 50 ff 75 ?? 6a 16 ff 75 ?? ff d6 3b c3 74 ?? 39 5d ?? 76 ?? ff 75 ?? 8d 4f 10 e8 ?? ?? ff ff be 00 04 00 00 56}  //weight: 10, accuracy: Low
        $x_1_4 = {44 6c 79 3d 00 00 00 00 44 65 46 3d 00 00 00 00 56 65 72 3d 00 00 00 00 53 74 67 3d 00 00 00 00 43 6d 64 3d 00 00 00 00 55 52 4c 3d 00 00 00 00 52 65 67 3d 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {77 77 77 2e 79 61 68 6f 6f 2e 63 6f 6d 2f 00 00 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_ZBB_2147803943_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZBB"
        threat_id = "2147803943"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {50 51 ff 15 ?? ?? ?? ?? 8d 94 24 10 01 00 00 52 ff d6 b9 41 00 00 00 33 c0 8d bc 24 14 02 00 00 f3 ab 8d 44 24 0c 8d 8c 24 14 02 00 00 50}  //weight: 10, accuracy: Low
        $x_10_2 = {8d 84 24 10 01 00 00 83 e1 03 50 f3 a4 68 f0 00 00 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 25 07 00 00 80 79 05 48 83 c8 f8 40 83 c0 04}  //weight: 10, accuracy: Low
        $x_1_3 = {2e 64 6c 6c 00 46 69 6e 64 00 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_ZBD_2147803945_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZBD"
        threat_id = "2147803945"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8b 74 24 08 85 f6 75 04 33 c0 5e c3 ff 15 ?? ?? ?? ?? 50 e8 ?? ?? 00 00 83 c4 04 e8 ?? ?? 00 00 99 b9 1a 00 00 00 f7 f9 83 c2 61 52 e8 ?? ?? 00 00 99 b9 1a 00 00 00 f7 f9 83 c2 61 52}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f9 03 76 3c 50 8d 4c 24 28 50 8d 94 24 90 00 00 00 51 52 50 e8 ?? ?? 00 00 85 c0 75 12 6a 01 50 50 8d 44 24 30 50 68 ?? ?? ?? ?? 6a 00 ff d5 68 d0 07 00 00 46 ff 15 ?? ?? ?? ?? e9 1d ff ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {25 63 25 63 25 63 25 63 00 00 00 00 25 73 5c 25 73 00 00 00 77 69 6e 68 6c 70 33 32 2e 65 78 65 00 00 00 00 6f 70 65 6e 00 00 00 00 6f 6f 00 00 25 73 5c 25 73 25 64 2e 65 78 65 00 63 25 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Agent_PI_2147804027_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.PI"
        threat_id = "2147804027"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 76 69 64 71 75 69 63 6b 2e 69 6e 66 6f 2f 63 67 69 2f [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "Error! Can't initialize plug-ins directory. Please try again later." ascii //weight: 1
        $x_1_3 = "\\inetc.dll" ascii //weight: 1
        $x_1_4 = "\\ExecPri.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ZEA_2147804043_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZEA"
        threat_id = "2147804043"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 45 78 41 00 74 72 6f 6a 64 69 65 2e 6b 78 70 2c 61 73 73 69 73 74 73 65 2e 65 78 65 2c 72 66 77 2e 65 78 65 2c 6b 61 76 70 66 77 2e 65 78 65 2c 6b 70 66 77 73 76 63 2e 65 78 65 2c 6b 61 76 73 74 61 72 74 2e 65 78 65 2c 6b 77 61 74 63 68 2e 65 78 65 2c 6b 61 76 70 6c 75 73 2e 65 78 65 00 6d 69 72 2e 65 78 65 2c 6d 69 72 2e 64 61 74 00 20 00 22 00 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 0d 0a 46 6f 72 74 68 67 6f 65 72 00 48 54 54 50 2f 31 2e 30 00}  //weight: 1, accuracy: High
        $x_1_2 = {1c 32 30 30 20 25 73 3d 25 73 3d 25 73 2f 25 73 3d 25 73 3d 25 73 2f 25 73 3d 25 73 00 68}  //weight: 1, accuracy: High
        $x_1_3 = {15 77 61 76 5c 4c 6f 67 2d 69 6e 2d 6c 6f 6e 67 32 2e 77 61 76 00 ff}  //weight: 1, accuracy: High
        $x_1_4 = {76 77 77 77 2e 67 61 6d 65 6e 65 74 65 2e 63 6f 6d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6c 6f 6f 6b 2f 6c 6f 67 69 6e 2e 61 73 70 00 00 00 00 00 00 2f 6c 6f 6f 6b 2f 70 69 70 2e 61 73 70 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 31 30 30 00 33 30 30 00 33 32 30 00 37 35 30 20 6f 6e 6c 69 6e 65 21 00 37 35 30 20 6f 66 66 6c 69 6e 65 21 00 38 30 31 00 38 30 32 00 38 30 33 00 38 30 34 00 38 35 30 00 38 35 30 20 6f 66 66 6c 69 6e 65 21 00 39 35 30 20 31 2e 35 30 00 39 37 34 00 39 39 30 00 39 39 31 20 31 00 39 39 31 20 30 00 3a 3a 00 39 30 30 20 55 73 65 72 3a 00 20 50 61 73 73 3a 00 34 30 30 20 00 2e 00 2f}  //weight: 1, accuracy: High
        $x_1_6 = {00 53 4f 46 54 57 41 52 45 5c 77 53 6b 79 73 6f 66 74 00 7e 78 51 00 50 4f 53 54 00 68 74 74 70 3a 2f 2f 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_GYJ_2147804058_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.GYJ"
        threat_id = "2147804058"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 ec 68 b9 19 00 00 00 33 c0 53 55 56 57 8d 7c 24 14 6a 64 f3 ab 8d 44 24 18 50 ff 15 80 30 40 00 bf 64 41 40 00 83 c9 ff 33 c0 8d 54 24 14 f2 ae f7 d1 2b f9 68 60 41 40 00 8b f7 8b d9 8b fa 83 c9 ff f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 68 8b 00 00 00 83 e1 03 50 f3 a4 ff 15 7c 30 40 00 8b f0 56 6a 00 ff 15 78 30 40 00 56 6a 00 8b d8 ff 15 74 30 40 00 53 6a 40 8b f0 ff 15 48 30 40 00 56 8b e8 ff 15 1c 30 40 00 8b cb 8b f0 8b c1 8b fd c1 e9 02 f3 a5 8b c8 6a 00 83 e1 03 6a 00 f3 a4 6a 02 6a 00 6a 00 8d 4c 24 28 68 00 00 00 40 51 ff 15 20 30 40 00}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\Program Files\\sys.bat" ascii //weight: 1
        $x_1_3 = "&net stop KPfwSvc&net stop KWatchsvc&net stop McShield&net stop \"Norton AntiVirus Server\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ZZB_2147804059_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZZB"
        threat_id = "2147804059"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Documents and Settings\\All Users\\zhqbdf16.ini" ascii //weight: 1
        $x_1_2 = "mydown" ascii //weight: 1
        $x_1_3 = "delay" ascii //weight: 1
        $x_1_4 = "zhqb_df" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\run" ascii //weight: 1
        $x_1_6 = "Startup" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_8 = "dfzhqb.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ZDD_2147804062_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZDD"
        threat_id = "2147804062"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "system32\\tcsvc.sys" wide //weight: 1
        $x_1_2 = "http://www.jajaan.com/ip.asp" wide //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "gg/gg.asp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ZDJ_2147804063_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZDJ"
        threat_id = "2147804063"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "http://www.KJDhendieldiouyu.COM/CFDATA.ima?ccode=%s&cfdatacc=%s&gmt=%d" ascii //weight: 1
        $x_1_3 = "asdfjkluiop.com" ascii //weight: 1
        $x_1_4 = "sweepstakess.com" ascii //weight: 1
        $x_1_5 = "hotxxxtv.com" ascii //weight: 1
        $x_1_6 = "freeporntoday.net" ascii //weight: 1
        $x_1_7 = "freepornnow.net" ascii //weight: 1
        $x_1_8 = "porn1.org" ascii //weight: 1
        $x_1_9 = "virgins" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ZDK_2147804064_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZDK"
        threat_id = "2147804064"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.c0rrupted.com" ascii //weight: 1
        $x_10_2 = {89 4c 24 04 b8 03 01 00 00 89 14 24 88 9d c8 fd ff ff bb 04 01 00 00 89 44 24 08 e8 d8 1a 00 00 89 5c 24 04 8d 9d c8 fd ff ff 89 1c 24 e8 26 1d 00 00 83 ec 08 89 5c 24 08 89 7c 24 04 bf 08 91 40 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_ZDK_2147804064_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZDK"
        threat_id = "2147804064"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 8d 4d e8 66 ba 2d 43 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 e8 e8 ?? ?? ?? ?? 50 8d 4d e4 66 ba 2d 43 b8 ?? ?? ?? ?? e8 3a fe ff ff 8b 45 e4 e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 6a 05 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10 68}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\WINDOWS\\system32\\imglog.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ZDK_2147804064_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZDK"
        threat_id = "2147804064"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://vidareal2010.pisem.su/imglog.exe" wide //weight: 1
        $x_10_2 = {c7 45 fc 07 00 00 00 68 1c 2c 40 00 e8 f1 06 00 00 0f bf c8 85 c9 75 48 c7 45 fc 08 00 00 00 ba 1c 2c 40 00 8d 4d 90 ff 15 98 10 40 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_ZDL_2147804065_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZDL"
        threat_id = "2147804065"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {ff 92 f8 00 00 00 8b 45 ec 56 50 8b 08 ff 91 00 01 00 00 8b 45 ec 6a ff 50 8b 10 ff 92 f0 00 00 00 8b 45 ec 56 50 8b 08 ff 91 bc 00 00 00 8b 45 ec 56 50 8b 10 ff 92 a4 00 00 00 8b 45 ec 50 68}  //weight: 10, accuracy: High
        $x_10_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_1_3 = "http://bot.cjfeeds.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_ZDM_2147804066_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZDM"
        threat_id = "2147804066"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 73 65 6e 64 65 72 00 63 3a 5c 6c 6f 67 2e 68 74 6d 00 43 3a 5c 70 73 74 6f 72 61 67 65 2e 65 78 65 00 50 53 74 6f 72 61 67 65 00 43 3a 5c 75 73 65 72 71 75 6f 74 61 2e 65 78 65 00 55 73 65 72 51 75 6f 74 61 00 2d 4c 49 42 47 43 43 57 33 32 2d 45 48 2d 32 2d 53 4a 4c 4a 2d 47 54 48 52 2d 4d 49 4e 47 57 33 32 00 00 00 77 33 32 5f 73 68 61 72 65 64 70 74}  //weight: 1, accuracy: High
        $x_1_2 = {52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f [0-64] 75 70 6c 6f 61 64 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ZCB_2147804067_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZCB"
        threat_id = "2147804067"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "chuangzaohuihuang" ascii //weight: 1
        $x_1_2 = "www.haoads.cn" ascii //weight: 1
        $x_1_3 = "chuangzaohuihuang.cn" ascii //weight: 1
        $x_1_4 = "micr0s0fts.cn" ascii //weight: 1
        $x_1_5 = "http://unstat.baidu.com" ascii //weight: 1
        $x_1_6 = {f2 ae f7 d1 2b f9 8b f7 8b fa 8b d1 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 8b ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_DDC_2147804073_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.DDC"
        threat_id = "2147804073"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {34 00 00 00 68 74 74 70 3a 2f 2f 63 63 63 2e 61 76 6e 31 32 2e 63 6e 2f 63 63 63 2f 71 71 71 63 63 63 2f 70 6f 73 74 2e 61 73 70 3f 69 3d 37 37}  //weight: 1, accuracy: High
        $x_1_2 = {68 1c 01 00 00 6a 00 6a 04 6a 00 6a ff e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = "CBT_Struct_for_QQ" ascii //weight: 1
        $x_1_4 = {77 69 6e 64 6f 77 73 5c 61 2e 74 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_KG_2147804077_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.KG"
        threat_id = "2147804077"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 13 00 00 20 8b ce c7 ?? ?? 04 00 00 00 e8 ?? ?? 00 00 85 c0 0f ?? ?? 00 00 00 8b 45 ?? 3d c8 00 00 00 0f ?? ?? 00 00 00 3d 2c 01 00 00 0f ?? ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 16 8b ce ff 52 54 85 f6 74 09 8b 06 6a 01 8b ce ff 50 04 8d 4d bc e8 ?? ?? 00 00 8b 4d e8 6a 03 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_KJ_2147804078_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.KJ"
        threat_id = "2147804078"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 19 3c 3e 74 15 81 fe e8 03 00 00 73 0d 8b 4d f4 43 89 5d f8 88 04 0e 46 eb e1}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 40 85 c0 74 15 ff ?? ?? 8d ?? ?? ff ff ff 50 e8 ?? ?? ff ff 59 85 c0 59 75 10 ff 45 ec ff 45 f8 83 7d ec 08 0f 8c 74 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_KK_2147804079_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.KK"
        threat_id = "2147804079"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://update.xiaoshoupeixun.com/tsbho.ini" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = {f7 d1 49 51 6a 29 b9 ?? ?? 00 10 e8 ?? ?? 00 00 50 68 24 0c 0b 83 56 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 00 68 c0 d4 01 00 68 02 10 00 00 56 ff d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_KL_2147804083_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.KL"
        threat_id = "2147804083"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 a8 61 00 00 f7 f9 81 c2 ac 0d 00 00 89 15 ?? ?? ?? ?? 89 54 ?? ?? ff 15 ?? ?? ?? ?? 8b d0 b8 d3 4d 62 10 f7 e2 c1 ea 06}  //weight: 1, accuracy: Low
        $x_1_2 = {99 b9 03 00 00 00 f7 f9 83 c2 07 69 d2 09 03 00 00 52}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_KN_2147804084_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.KN"
        threat_id = "2147804084"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 24 52 50 c7 45 ?? 3a 2f 2f 77 c7 45 ?? 65 62 72 65 c7 45 ?? 67 2e 33 33 c7 45 ?? 32 32 2e 6f c7 45 ?? 72 67 2f 69 c7 45 ?? 6e 64 65 78 c7 45 ?? 2e 61 73 70 89 75 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ZZF_2147804085_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ZZF"
        threat_id = "2147804085"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 18 00 00 00 8b 40 30 0f b6 40 02 85 c0 0f 85 b7 02 00 00 31 c0 40 50 50 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 f8 57}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 20 00 00 68 ?? ?? 40 00 ff 35 ?? ?? 40 00 ff 15 ?? ?? 40 00 85 c0 75 05 e9 ?? 00 00 00 83 3d ?? ?? 40 00 00 74 41}  //weight: 1, accuracy: Low
        $x_1_3 = "update.microsoft.com" ascii //weight: 1
        $x_1_4 = "AgavaDwnl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_OG_2147804089_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.OG"
        threat_id = "2147804089"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b 73 69 6e 6e 65 2e 63 6f 6d 2f 62 73 33 30 2e 70 68 70 00 3f 72 6e 64 31 3d 25 78 26 72 6e 64 32 3d 25 64}  //weight: 1, accuracy: High
        $x_1_2 = {74 14 6a 00 6a 00 68 ?? ?? ?? ?? 8d 45 ?? 50 6a 00 e8 ?? 00 00 00 68 20 4e 00 00 ff 15 ?? ?? ?? ?? b9 01 00 00 00 85 c9 74 0d 68 00 04 00 00 ff 15 ?? ?? ?? ?? eb ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_PB_2147804090_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.PB"
        threat_id = "2147804090"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 73 79 73 74 65 6d 2e 65 78 65 22 00 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 74 74 70 3a 2f 2f 66 69 73 68 68 61 70 70 79 38 38 38 2e 67 69 63 70 2e 6e 65 74 2f 70 65 2e 65 78 65 00 68 74 74 70 3a 2f 2f 68 61 70 70 79 74 69 67 65 72 79 65 61 72 2e 33 33 32 32 2e 6f 72 67 2f 70 65 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 43 6f 6d 6d 61 6e 64 3d 73 79 73 74 65 6d 2e 65 78 65 00 00 00 00 77 74 00 00 5c 41 75 74 6f 72 75 6e 2e 69 6e 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_PC_2147804092_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.PC"
        threat_id = "2147804092"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 64 53 6a 04 8d 4c 24 20 51 8d 44 24 30 6a ff}  //weight: 1, accuracy: High
        $x_1_2 = {83 e0 0f 0f b7 04 47 83 c1 02 8b e9 66 89 45 00 0f b6 2a 83 c1 02 c1 ed 04 66 8b 2c 6f 8b c1 66 89 28}  //weight: 1, accuracy: High
        $x_1_3 = "d1.downxia.net" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_PD_2147804093_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.PD"
        threat_id = "2147804093"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://stat.wamme.cn/C8C/gl/cnzz60.html" ascii //weight: 1
        $x_1_2 = "system32\\drivers\\etc\\service2.ini" ascii //weight: 1
        $x_1_3 = {68 00 b6 32 01 f3 a5 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_PH_2147804094_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.PH"
        threat_id = "2147804094"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 68 02 00 00 00 bb 6c 02 00 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {68 74 74 70 3a 2f 2f 25 37 36 25 32 45 25 37 39 25 36 31 25 36 46 25 33 36 25 33 33 25 32 45 25 36 33 25 36 46 25 36 44 2f 75 72 6c 2e 61 73 70 00 25 43 35 25 45 34 25 44 36 25 43 33 25 44 30 25 43 35 25 43 46 25 41 32}  //weight: 1, accuracy: High
        $x_1_3 = {6b 77 73 74 72 61 79 2e 65 78 65 00 68 74 74 70 3a 2f 2f 77 77 77 2e 33 33 32 32 2e 6f 72 67 2f 64 79 6e 64 6e 73 2f 67 65 74 69 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_QY_2147804095_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.QY"
        threat_id = "2147804095"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 e8 81 f9 9d 71 82 4e 74 1c 81 f9 9c 71 82 4e 74 14 81 f9 9b c7 81 fa 74 0c}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 00 8a 14 38 03 c7 88 51 ff 8a 40 01 88 01 83 c7 04 83 c1 02 3b 7d 04 76 e5}  //weight: 1, accuracy: High
        $x_1_3 = {c7 40 04 00 ?? 02 00 c7 00 01 00 00 00 89 48 08 ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Agent_QZ_2147804096_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.QZ"
        threat_id = "2147804096"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 05 57 33 c9 56 8d 41 01 8d 95 fc fe ff ff c7 86 58 15 00 00 c8 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "http://127.0.0.1/down/list2.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_CBD_2147804097_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.CBD"
        threat_id = "2147804097"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 4e 53 49 53 64 6c 2e 64 6c 6c 00 fd 82 80 00 68 74 74 70 3a 2f 2f 70 73 76 73 74 61 74 73 2e 69 6e 66 6f 2f 68 72 74 62 62 6e 2f 72 77 76 73 6b 69 2e 65 78 65 00 64 6f 77 6e 6c 6f 61 64 00 fd 8a 80 00 73 75 63 63 65 73 73 00 fd 82 80 20 2f 71 00 52 75 6e 74 69 6d 65 20 56 42 35 20 4f 4b 2e 00 30 00 fd 9a 80 5c 44 69 61 6c 65 72 2e 64 6c 6c 00 41 74 74 65 6d 70 74 43 6f 6e 6e 65 63 74 00 6f 6e 6c 69 6e 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_JW_2147804111_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.JW"
        threat_id = "2147804111"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 3a 5c 74 6d 70 7a 5c 62 6f 6f 74 2e 63 6d 64 00 00 00 00 64 65 6c 20 2f 51 20 2f 46 20 63 3a 5c 74 6d 70 7a 5c 62 6f 6f 74 2e 63 6d 64}  //weight: 1, accuracy: High
        $x_1_2 = {63 3a 5c 70 73 2e 63 6d 64 00 00 00 64 65 6c 20 2f 51 20 2f 46 20 25 73 0a 00 00 00 64 65 6c 20 2f 51 20 2f 46 20 63 3a 5c 70 73 2e 63 6d 64 0a 00 00 00 00 63 3a 5c 6e 74 6c 64 72 78 64 73 00}  //weight: 1, accuracy: High
        $x_1_3 = "127.0.0.1 updates.symantec.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_ACG_2147804153_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.ACG"
        threat_id = "2147804153"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "331"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "verysilent" ascii //weight: 100
        $x_100_2 = "AutoInsQyule" ascii //weight: 100
        $x_100_3 = "{3B7CBEE9-89A2-449c-B88E-22498FBAB005}" ascii //weight: 100
        $x_10_4 = "setup.exe" ascii //weight: 10
        $x_10_5 = "QyuleInstall.exe" ascii //weight: 10
        $x_10_6 = "InternetReadFile" ascii //weight: 10
        $x_1_7 = "http://update.qyule.com/setup.exe" ascii //weight: 1
        $x_1_8 = "http://218.204.253.145/setup.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_FX_2147804155_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.FX"
        threat_id = "2147804155"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "303"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "\\mf*.dll" ascii //weight: 100
        $x_100_2 = "\\winaccestor.dat" ascii //weight: 100
        $x_100_3 = "CLSID\\{A8981DB9-B2B3-47D7-A890-9C9D9F4C5552}" ascii //weight: 100
        $x_1_4 = "regsvr32 /s" ascii //weight: 1
        $x_1_5 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_6 = "Software\\Privacy Project" ascii //weight: 1
        $x_1_7 = "Smart Content Protector" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_GF_2147804156_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.GF"
        threat_id = "2147804156"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "192.168.0.102" ascii //weight: 10
        $x_10_2 = "208.66.194.215" ascii //weight: 10
        $x_10_3 = "http://%s/Mail/%s" ascii //weight: 10
        $x_10_4 = "javascript:onSubmitToolbarItemClicked(" ascii //weight: 10
        $x_10_5 = "Z:\\NewProjects\\hotsend\\Release-Win32\\hotsend.pdb" ascii //weight: 10
        $x_1_6 = "XORarrays" ascii //weight: 1
        $x_1_7 = "RSAencrypt" ascii //weight: 1
        $x_1_8 = "parseRSAKeyFromString" ascii //weight: 1
        $x_1_9 = "WScript.Echo(Encrypt(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_KX_2147804170_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.KX"
        threat_id = "2147804170"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 a4 76 0d 8a 0c 10 32 c8 88 0c 10 40 3b c3 72 f3}  //weight: 1, accuracy: High
        $x_1_2 = {c6 44 24 15 3a c6 44 24 16 5c be 03 00 00 00 e8 ?? ?? 00 00 8b d0 8b fb 83 c9 ff 33 c0 f2 ae f7 d1 8b c2 49 33 d2 f7 f1 46 83 fe 09 8a 04 1a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_KY_2147804171_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.KY"
        threat_id = "2147804171"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " /c ping localhost -n 3 >> NUL && del " ascii //weight: 1
        $x_1_2 = {63 32 68 6c 62 47 77 7a 4d 69 35 6b 62 47 77 3d 00 56 56 4a 4d 52 47 39 33 62 6d 78 76 59 57 52 55 62 30 5a 70 62 47 56 42 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_NN_2147804183_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.NN"
        threat_id = "2147804183"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 61 6f 68 61 6e 67 ?? 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 65 72 65 72 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = {45 78 70 6c 6f 72 65 72 5c 44 6f 6e 74 53 68 6f 77 4d 65 54 68 69 73 44 69 61 6c 6f 67 41 67 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 57 69 6e 52 41 52 5c 57 69 6e 52 41 52 2e 6b 6e 6c 22 00}  //weight: 1, accuracy: High
        $x_1_5 = {69 65 78 70 6c 6f 72 65 2e 65 78 65 20 68 74 74 70 3a 2f 2f 77 77 77 2e 70 70 [0-4] 2e 63 6f 6d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_AAI_2147804194_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.AAI"
        threat_id = "2147804194"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AudioCD\\DefaultIcon" wide //weight: 2
        $x_2_2 = "Host Process for Win32 Services" wide //weight: 2
        $x_2_3 = "spoolcv.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_AAJ_2147804195_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.AAJ"
        threat_id = "2147804195"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "www.msnnetwork.net" ascii //weight: 2
        $x_3_2 = "ZVwkVbxt3XdNbEksVZhiTmMpc0tiNMYD" ascii //weight: 3
        $x_2_3 = "now upgrading.....!" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_SN_2147804211_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.SN"
        threat_id = "2147804211"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "c:\\feji.log" ascii //weight: 10
        $x_1_2 = {5c 70 69 70 69 5f 64 61 65 5f ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 48 61 70 70 79 (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 68 79 74 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {20 2f 76 65 72 79 73 69 6c 65 6e 74 [0-4] 5c 70 69 70 69 5f 73 65 74 75 70 25 73 25 73 25 73 25 73 5f 63 6c 65 61 6e 5f ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_SO_2147804212_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.SO"
        threat_id = "2147804212"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 6c 6f 61 64 64 6b 2e 69 6e 66 08 00 (44 6b|4d 79) 54 65 6d 70}  //weight: 10, accuracy: Low
        $x_1_2 = "\\run32%d.exe" ascii //weight: 1
        $x_1_3 = "\\note64.exe" ascii //weight: 1
        $x_1_4 = "\\notepad32.exe" ascii //weight: 1
        $x_1_5 = "%s\\notepad%d.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_TG_2147804213_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.TG"
        threat_id = "2147804213"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "d:\\360\\360Safe.reg" ascii //weight: 1
        $x_1_2 = {68 c8 00 00 00 e8 ?? ?? ff ff e8 ?? ?? ff ff 68 c8 00 00 00 e8 ?? ?? ff ff e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_TK_2147804214_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.TK"
        threat_id = "2147804214"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "68.68.101.226:777/loading/" ascii //weight: 1
        $x_1_2 = ":777/nhbvyeuds.php" ascii //weight: 1
        $x_1_3 = ":251/popopo.php?gg=" ascii //weight: 1
        $x_1_4 = ":251/bukuaile.php?df=" ascii //weight: 1
        $x_1_5 = ":251/rfrfrfrfrf.php?gg=" ascii //weight: 1
        $x_1_6 = ":251/demamacao.php.php?df=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Agent_TS_2147804215_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.TS"
        threat_id = "2147804215"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{abc-_-cba}" ascii //weight: 1
        $x_1_2 = "Server_Crack.rar" ascii //weight: 1
        $x_1_3 = "\\WinH%c%c%c32.exe" ascii //weight: 1
        $x_1_4 = "C:\\Program Files\\7rar\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_AAR_2147804219_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.AAR"
        threat_id = "2147804219"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ico.cab" ascii //weight: 1
        $x_1_2 = "url.cab" ascii //weight: 1
        $x_1_3 = "\\zs.bat" ascii //weight: 1
        $x_1_4 = {75 6b 61 64 2e 63 6f 6d [0-4] 2f 6b 69 6e 67 73 6f 66 74 2e 63 61 62}  //weight: 1, accuracy: Low
        $x_1_5 = {63 68 61 74 5f ?? ?? ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65 40 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_YN_2147804221_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.YN"
        threat_id = "2147804221"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 f4 df 6d f0 dd 5d f8 9b 8d 45 ec 50 dd 45 f8 db 7d e0 9b 8d 45 e0 89 45 f0 c6 45 f4 03 8d 55 f0 33 c9 b8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 06 8b c8 80 c1 d0 80 e9 37 73 35 8a 4e 01 80 c1 d0 80 e9 37 73 2a 25 ff 00 00 00 66 8b 04 45 ?? ?? ?? ?? c1 e0 04 33 c9 8a 4e 01 66 8b 0c 4d ?? ?? ?? ?? 02 c1 88 02 42 83 c6 02 4f 85 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 13 8a 54 32 ff 32 55 f7 88 54 30 ff 46 4f 75 e8 8b c3 8b 55 f8 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_AAN_2147804225_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.AAN"
        threat_id = "2147804225"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 00 00 00 73 65 74 75 70 2e 65 78 65 00 00 00 ff ff ff ff 26 00 00 00 68 74 74 70 3a 2f 2f 64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f [0-10] 2f 7a 2e 6a 70 67}  //weight: 5, accuracy: Low
        $x_5_2 = {e8 ed fe ff ff 6a 00 8d 45 f4 8b 4d fc 8b 15 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 45 f4 e8 ?? ?? ?? ff 50 e8 ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_1_3 = "C:\\Progt\\" ascii //weight: 1
        $x_1_4 = "C:\\ProgFUGI\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_YW_2147804228_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.YW"
        threat_id = "2147804228"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 3d 7e 00 75 02 33 c0 8a 19 8b d0 81 e2 ff ff 00 00 8a 54 54 0c 32 da 40 88 19 41 4e 75 e1}  //weight: 1, accuracy: High
        $x_1_2 = {50 c6 00 57 c6 86 ?? ?? ?? ?? 49 c6 86 ?? ?? ?? ?? 4e c6 86 ?? ?? ?? ?? 49 c6 86 ?? ?? ?? ?? 4e c6 86 ?? ?? ?? ?? 45 c6 86 ?? ?? ?? ?? 54 c6 86 ?? ?? ?? ?? 2e c6 86 ?? ?? ?? ?? 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_AAQ_2147804230_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.AAQ"
        threat_id = "2147804230"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 73 00 65 00 74 00 75 00 70 00 00 00 00 00 25 00 73 00 5c 00 61 00 70 00 70 00 25 00 64 00 2e 00 74 00 6d 00 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {eb 19 8a d1 c0 ea 02 08 10 40 c0 e1 06 88 08 ba 03 00 00 00 eb 05 08 08}  //weight: 1, accuracy: High
        $x_1_3 = {c7 84 24 40 03 00 00 00 00 00 00 8b 54 24 20 52 50 e8 69 00 00 00 c7 84 24 40 03 00 00 ff ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_DAA_2147804231_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.DAA"
        threat_id = "2147804231"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 3b 3e 2d 2d 3e 00}  //weight: 1, accuracy: High
        $x_1_2 = {7e 1b 8b 4c 24 04 8b 54 24 08 56 2b d1 8b f0 8a 04 0a 32 44 24 10 88 01 41 4e 75 f3 5e c3}  //weight: 1, accuracy: High
        $x_1_3 = {68 1c 40 40 00 50 e8 ?? 0e 00 00 8d 85 e4 fe ff ff 50 8d 85 70 fa ff ff 50 e8 ?? 0d 00 00 8d 85 70 fa ff ff 68 14 40 40 00 50 e8 ?? 0d 00 00 83 c4 28 8d 45 e8 50 8d 85 a0 fe ff ff 50 53 53 53 53 53 8d 85 70 fa ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_OP_2147804232_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.OP"
        threat_id = "2147804232"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%MYFILES%\\Upd" ascii //weight: 1
        $x_1_2 = "pipi_dae" ascii //weight: 1
        $x_1_3 = "Happy88hyt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_AAE_2147804235_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.AAE"
        threat_id = "2147804235"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 18 32 da 88 18 40 49 75 f6}  //weight: 2, accuracy: High
        $x_1_2 = {c6 44 24 29 2f c6 44 24 2a 63 88 ?? 24 2b c6 44 24 2c 64 c6 44 24 2d 65}  //weight: 1, accuracy: Low
        $x_1_3 = "%s&OS=wINxp&IP=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_AAF_2147804236_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.AAF"
        threat_id = "2147804236"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Program Files\\urlcore.exe /h /r /t /b" ascii //weight: 1
        $x_1_2 = "\\Internet Explorer.lnk" ascii //weight: 1
        $x_1_3 = "\\HideDesktopIcons\\ClassicStartMenu" ascii //weight: 1
        $x_1_4 = {6a 00 6a 00 68 f5 00 00 00 ?? e8 ?? ?? ?? ?? 6a 00 6a 00 68 f5 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_AFN_2147804237_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.AFN"
        threat_id = "2147804237"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0e 8a 10 2a d1 88 10 8a ca 8a 16 32 d1 46 88 10 40}  //weight: 1, accuracy: High
        $x_1_2 = {46 c6 44 24 ?? 69 c6 44 24 ?? 65 c6 44 24 ?? 41 c6 44 24 ?? 00 c6 44 24 ?? 75 c6 44 24 ?? 72}  //weight: 1, accuracy: Low
        $x_1_3 = {6d c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 5c c6 44 24 ?? 75}  //weight: 1, accuracy: Low
        $x_1_4 = "\\Tasks\\conime.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Agent_AAG_2147804238_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.AAG"
        threat_id = "2147804238"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "aaaaaaaaaaaaaaaaaaaaaa.limewebs.com/z/gate.php" ascii //weight: 1
        $x_1_2 = {0d 2f 00 00 74 ?? 81 bd ?? ?? ff ff 0c 2f 00 00 74 ?? 81 bd ?? ?? ff ff 05 2f 00 00 74 ?? 81 bd ?? ?? ff ff 06 2f 00 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_OR_2147804239_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.OR"
        threat_id = "2147804239"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%RootSystem%\\hook.dll" ascii //weight: 1
        $x_1_2 = "//xc.115.bz/tools.exe" ascii //weight: 1
        $x_1_3 = "\\userinit.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_AFO_2147804240_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.AFO"
        threat_id = "2147804240"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 f6 74 09 66 81 7c 24 24 4d 5a 75 27 8b 54 24 10}  //weight: 1, accuracy: High
        $x_1_2 = "//a.zz7.in/count.asp" ascii //weight: 1
        $x_1_3 = "//tx.xx7.in/a7lm.txt" ascii //weight: 1
        $x_1_4 = "mac=%s&ver=%s&os=%s&tm=%s&id=%s&hd=%s&" ascii //weight: 1
        $x_1_5 = "taskkill /F /IM %s" ascii //weight: 1
        $x_1_6 = "smss.exe|csrss.exe|winlogon.exe|services.exe|svchost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Agent_AFP_2147804241_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.AFP"
        threat_id = "2147804241"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 cb 08 e9 ?? 00 00 00 80 e3 f7 eb 7f f6 04 31 04 74 05 80 cb 04 eb 74 80 e3 fb eb 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 11 80 c2 17 30 10 41 40 4f 75 ed}  //weight: 1, accuracy: High
        $x_1_3 = "%APPDATA%\\Microsoft\\Media Player\\DRM128" ascii //weight: 1
        $x_1_4 = "/patch/chkupdate.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_AFU_2147804242_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.AFU"
        threat_id = "2147804242"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "222.217.240.30/song/gougou.exe" ascii //weight: 1
        $x_1_2 = "222.217.240.30/song/vgauga.exe" ascii //weight: 1
        $x_1_3 = "222.217.240.30/song/pison.exe" ascii //weight: 1
        $x_1_4 = {00 44 6f 77 6e 6c 6f 61 64 69 6e 67 20 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_EAA_2147804273_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.EAA"
        threat_id = "2147804273"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 1e 83 c6 04 51 e8 ?? ?? ?? ?? 59 01 45 ?? 89 07 83 c7 04 49 75 e9}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 0b 83 c3 04 8b 32 83 c2 04 f3 a4 48 75 f1}  //weight: 2, accuracy: High
        $x_1_3 = {20 3e 6e 75 6c 20 32 3e 6e 75 6c 0d 0a}  //weight: 1, accuracy: High
        $x_1_4 = "@rd /f/s/q " ascii //weight: 1
        $x_1_5 = "@ping 127.0.0.1 -n 2" ascii //weight: 1
        $x_1_6 = ".win0day.com/" ascii //weight: 1
        $x_1_7 = " Files\\update.exe" ascii //weight: 1
        $x_1_8 = "\\win123b.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Agent_G_2147804294_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.G!MTB"
        threat_id = "2147804294"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 88 04 3e 46 81 fe 58 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_MG_2147805568_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.MG!MTB"
        threat_id = "2147805568"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://tj.gogo2021.xyz/" ascii //weight: 1
        $x_1_2 = "\\WINDOWS\\Temp\\MpCz01.tmp" ascii //weight: 1
        $x_1_3 = "\\TEMP\\~1z23.tmp" ascii //weight: 1
        $x_1_4 = "Sleep" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_6 = "passThrough.pdb" ascii //weight: 1
        $x_1_7 = "CreateFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_MF_2147807758_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.MF!MTB"
        threat_id = "2147807758"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 56 8b 74 24 10 8b 4c 24 14 8b 7c 24 0c 8b c1 8b d1 03 c6 3b fe ?? 08 3b f8 0f 82 ?? ?? ?? ?? 0f ba 25 ?? ?? ?? ?? 01 73 ?? f3 a4 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {66 39 11 74 ?? 40 83 c1 02 3b 45 0c 72}  //weight: 1, accuracy: Low
        $x_1_3 = "SecurityHealth.exe" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_6 = "URLDownloadToFile" ascii //weight: 1
        $x_1_7 = "WriteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_EF_2147812345_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.EF!MTB"
        threat_id = "2147812345"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//asbit.cn/zipack/full" ascii //weight: 1
        $x_1_2 = "cmd.exe /c rmdir /s /q" ascii //weight: 1
        $x_1_3 = "Fast Desktop" ascii //weight: 1
        $x_1_4 = "Qkkbal" ascii //weight: 1
        $x_1_5 = "__entry@8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_QE_160915_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.QE"
        threat_id = "160915"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\inetc.dll" ascii //weight: 1
        $x_1_2 = {2e 77 67 65 74 74 2e 63 6f 2e 63 63 2f [0-16] 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_3 = "token=" ascii //weight: 1
        $x_1_4 = "/SILENT" ascii //weight: 1
        $x_1_5 = ".exe\" /S" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Agent_QE_160915_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agent.QE"
        threat_id = "160915"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "#\\OfferBox\\config.xml" ascii //weight: 10
        $x_1_2 = {2f 74 72 61 63 6b 73 74 61 74 73 2e 70 68 70 00 69 64 3d 31 26 74 6f 6b 65 6e 3d}  //weight: 1, accuracy: High
        $x_1_3 = "\\OB.exe" ascii //weight: 1
        $x_1_4 = {5c 63 6f 75 6e 74 5f 74 6f 74 61 6c 2e 74 78 74 00 68 74 74 70 3a}  //weight: 1, accuracy: High
        $x_1_5 = ".uz4.net/log34756.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

