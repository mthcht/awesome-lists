rule TrojanClicker_Win32_Agent_AA_2147550213_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Agent.AA"
        threat_id = "2147550213"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "http://upcfg.j7y.net/upcfg/NewUpcfg.asp?ID=%d" ascii //weight: 4
        $x_2_2 = "CheckIEAdvThd" ascii //weight: 2
        $x_1_3 = "DownLoad Successfully" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Agent_KA_2147599212_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Agent.KA"
        threat_id = "2147599212"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual C++ Runtime Library" ascii //weight: 1
        $x_1_2 = "adcr.naver.com" wide //weight: 1
        $x_1_3 = "click.adkey.co.kr" wide //weight: 1
        $x_1_4 = "han-key.com" ascii //weight: 1
        $x_1_5 = "shopping.daum.net" wide //weight: 1
        $x_1_6 = "gmarket.co.kr" wide //weight: 1
        $x_1_7 = "Software\\Microsoft\\Internet Explorer\\Toolbar" wide //weight: 1
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" wide //weight: 1
        $x_1_9 = "DllRegisterServer" ascii //weight: 1
        $x_1_10 = "InternetCloseHandle" ascii //weight: 1
        $x_1_11 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Agent_AAD_2147600989_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Agent.AAD"
        threat_id = "2147600989"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 68 00 01 00 00 be ?? ?? ?? ?? 6a 00 56 e8 ?? ?? ?? ?? 8b 44 24 14 83 c4 0c 8a 08 84 c9 74 11 8b d6 2b d0 fe c9 88 0c 02 8a 48 01 40 84 c9 75 f3 8b c6 5e c3}  //weight: 1, accuracy: Low
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_4 = "\\system32\\catclogd.dll" ascii //weight: 1
        $x_1_5 = "rundll32.exe %s,Start" ascii //weight: 1
        $x_1_6 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "FtpGetFileA" ascii //weight: 1
        $x_1_9 = "SeDebugPrivilege" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Agent_FB_2147641108_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Agent.FB!dll"
        threat_id = "2147641108"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mysysgroup3" ascii //weight: 1
        $x_1_2 = "u.gogle.cn/" ascii //weight: 1
        $x_1_3 = "check.pathtome.com/" ascii //weight: 1
        $x_1_4 = "\\nethome32.dll.up" ascii //weight: 1
        $x_1_5 = "\\microinfo\\microinfo.dll.up" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Agent_DF_2147641423_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Agent.DF"
        threat_id = "2147641423"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 00 68 74 74 70 3a 2f 2f 67 6f 2e 25 36 43 25 36 31 25 36 39 25 36 43 25 36 35 25 36 31 2e 25 36 39 25 36 45 25 36 36 25 36 46 2f 3f 69 3d}  //weight: 1, accuracy: High
        $x_1_2 = {53 65 74 75 70 00 45 78 65 63 53 68 65 6c 6c 3a 20 00 43 6f 70 79 20 44 65 74 61 69 6c 73 20 54 6f 20 43 6c 69 70 62 6f 61 72 64 00 43 75 73 74 6f 6d 00 4e 61 6d 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Agent_EG_2147642220_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Agent.EG"
        threat_id = "2147642220"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Policies\\System\" /v DisableRegistryTools /t reg_dword /d 00000000 /f" ascii //weight: 1
        $x_1_2 = "\\Advanced\" /v ShowSuperHidden /t reg_dword /d 00000000 /f" ascii //weight: 1
        $x_1_3 = "echo [HKEY_CLASSES_ROOT\\lnkfile]>>%systemroot%" ascii //weight: 1
        $x_2_4 = "Explorer\\\\IEXPLORE.EXE \\\"http://www.5qbb.com\"" ascii //weight: 2
        $x_1_5 = "msiexec /regserver" ascii //weight: 1
        $x_1_6 = "\\Image File Execution Options\\360tray.exe\" /v Debugger /t reg_sz /d" ascii //weight: 1
        $x_1_7 = "\\Image File Execution Options\\chrome.exe\" /v Debugger /t reg_sz /d" ascii //weight: 1
        $x_1_8 = "start \"%ProgramFiles%\\Internet Explorer\\IEXPLORE.exe\" http://hao123" ascii //weight: 1
        $x_1_9 = "ATTRIB -H -R -S -A c:\\GRLDR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_Agent_EM_2147642523_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Agent.EM"
        threat_id = "2147642523"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {66 81 38 4d 5a 0f 85 ?? ?? 00 00 8b 45 ?? 8b 40 3c 8b 55 ?? 03 c2 8b 80 80 00 00 00}  //weight: 3, accuracy: Low
        $x_1_2 = "ip.hetodo.com:8754/ip.php" ascii //weight: 1
        $x_1_3 = ".hetodo.com:8080/sogouconfig/click_new_" ascii //weight: 1
        $x_1_4 = "/count.asp?mac=%s&ver=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_Agent_EN_2147642527_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Agent.EN"
        threat_id = "2147642527"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 17 8d 8c 24 ?? ?? 00 00 51 6a 00 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "NewStart\\ADSCut_SingleQQ\\release\\ADSCut.pdb" ascii //weight: 1
        $x_1_3 = {51 51 d3 b0 d2 f4 c9 fd bc b6 b0 fc a3 ac c7 eb cf c2 d4 d8 b0 b2 d7 b0 a1 a3 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Agent_MZA_2147643698_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Agent.MZA"
        threat_id = "2147643698"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Debugs.inf" ascii //weight: 1
        $x_1_2 = "%s\\cclick.exe" ascii //weight: 1
        $x_1_3 = ".021ads.com" ascii //weight: 1
        $x_1_4 = ".12580bj.com/" ascii //weight: 1
        $x_1_5 = "%s?mac=%s&ver=%s&Os=%s&FileNum=%d&Num=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Agent_S_2147646557_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Agent.S"
        threat_id = "2147646557"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 62 65 73 74 64 66 67 2e 69 6e 66 6f 3a [0-4] 2f [0-16] 2e 70 68 70 3f 67 67 3d}  //weight: 10, accuracy: Low
        $x_1_2 = "s=s+hex[a/16%16]+hex[a%16]+#[b>0,'-','']" ascii //weight: 1
        $x_1_3 = "sdfairport.info:777" ascii //weight: 1
        $x_1_4 = "\\SelfDel.dll" ascii //weight: 1
        $x_1_5 = "\\rrfds_" ascii //weight: 1
        $x_1_6 = "TrackPopupMenu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_Agent_Y_2147650159_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Agent.Y"
        threat_id = "2147650159"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\s_g_l_209.bat" ascii //weight: 1
        $x_1_2 = "\\xzok.bat" ascii //weight: 1
        $x_1_3 = "c:\\zwok" ascii //weight: 1
        $x_1_4 = "nuold919" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Agent_Z_2147650296_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Agent.Z"
        threat_id = "2147650296"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "typeID=textvr&uid=" ascii //weight: 3
        $x_2_2 = "websitelastm" ascii //weight: 2
        $x_2_3 = "&memParamID=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Agent_AN_2147651890_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Agent.AN"
        threat_id = "2147651890"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-16] 66 61 73 74 6e 73 [0-4] 2e 65 78 65}  //weight: 5, accuracy: Low
        $x_1_2 = "search.searchfinder.biz" ascii //weight: 1
        $x_1_3 = "bestfindzone.com/search.php" ascii //weight: 1
        $x_1_4 = "browseresults.com" ascii //weight: 1
        $x_1_5 = "thedreamsearch.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

