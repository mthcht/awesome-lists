rule Trojan_Win32_StartPage_ZK_2147716525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StartPage.ZK!bit"
        threat_id = "2147716525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StartPage"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3g234.com" wide //weight: 1
        $x_1_2 = "Secondary Start Pages" wide //weight: 1
        $x_1_3 = "wzjujumao_cb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StartPage_ZM_2147717248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StartPage.ZM!bit"
        threat_id = "2147717248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StartPage"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "homelockxx.dat" wide //weight: 1
        $x_1_2 = "kusrtrst.dat" wide //weight: 1
        $x_1_3 = "SOFTWARE\\homelock" ascii //weight: 1
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services\\hpcnt110" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StartPage_MX_2147720563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StartPage.MX!bit"
        threat_id = "2147720563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StartPage"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\TaskBar" wide //weight: 1
        $x_1_3 = "Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\StartMenu" wide //weight: 1
        $x_2_4 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 4d 00 61 00 69 00 6e 00 00 00 53 00 74 00 61 00 72 00 74 00 20 00 50 00 61 00 67 00 65 00}  //weight: 2, accuracy: High
        $x_2_5 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 70 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 4d 00 61 00 69 00 6e 00 5c 00 53 00 65 00 63 00 6f 00 6e 00 64 00 61 00 72 00 79 00 53 00 74 00 61 00 72 00 74 00 50 00 61 00 67 00 65 00 73 00 00 00 00 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5f 00 50 00 61 00 67 00 65 00 5f 00 55 00 52 00 4c 00}  //weight: 2, accuracy: High
        $x_10_6 = {0f af c0 0f b7 c0 99 6a ?? 59 f7 f9 8b 45 ?? 83 c2 ?? 66 89 14 78 8b c3 8b d6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_StartPage_MY_2147722507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StartPage.MY!bit"
        threat_id = "2147722507"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StartPage"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xiaoxiangbz.com/?ut=" wide //weight: 1
        $x_1_2 = "Start Page" wide //weight: 1
        $x_1_3 = "Software\\Microsoft\\Internet Explorer\\Main" wide //weight: 1
        $x_1_4 = "Software\\Wow6432Node\\Internet Explorer\\Main" wide //weight: 1
        $x_1_5 = "delselt.bat" wide //weight: 1
        $x_1_6 = "\\Internet Explorer.lnk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StartPage_PVQ_2147724603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StartPage.PVQ!bit"
        threat_id = "2147724603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StartPage"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\TaskBar" wide //weight: 1
        $x_1_2 = "HKCU\\Software\\Microsoft\\Internet Explorer\\Main\\Start Page" wide //weight: 1
        $x_1_3 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Internet Explorer\\Main\\Default_Page_URL" wide //weight: 1
        $x_1_4 = "HKCU\\Software\\Policies\\Microsoft\\Internet Explorer\\Control Panel\\HomePage" wide //weight: 1
        $x_1_5 = "browser.startup.homepage" wide //weight: 1
        $x_1_6 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 20 00 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 [0-16] 2f 00 70 00 72 00 69 00 6f 00 72 00 69 00 74 00 79 00 20 00 68 00 69 00 67 00 68 00}  //weight: 1, accuracy: Low
        $x_1_7 = "schtasks /Create /ST" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StartPage_PVP_2147724666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StartPage.PVP!bit"
        threat_id = "2147724666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StartPage"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sethome" ascii //weight: 1
        $x_1_2 = "%s\" -hide" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = {53 74 61 72 74 20 50 61 67 65 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StartPage_PVU_2147725476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StartPage.PVU!bit"
        threat_id = "2147725476"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StartPage"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\OpenHomePage\\Command\" , \"\" , \"Reg_sz\" , \"\"\"\" & @PROGRAMFILESDIR & \"\\Internet Explorer\\IEXPLORE.EXE\"\" http://www.qq5.com\" )" wide //weight: 1
        $x_1_2 = "REGWRITE ( \"HKCU\\Software\\Microsoft\\Internet Explorer\\Main\" , \"Start Page\" , \"Reg_sz\" , $HELPJPG" wide //weight: 1
        $x_1_3 = "{402128F8-5DD7-4039-B4BE-80E4366186AF}\" , \"URL\" , \"Reg_sz\" , \"http://www.go2000.cn/p/?q={searchTerms}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_StartPage_PVV_2147728908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StartPage.PVV!bit"
        threat_id = "2147728908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StartPage"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 a0 33 36 30 54 c7 45 a4 72 61 79 2e}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 b0 51 51 50 43 c7 45 b4 54 72 61 79}  //weight: 1, accuracy: High
        $x_1_3 = {8a 94 0d fc fe ff ff 30 ?? ?? ?? ?? ?? 41 81 f9 00 01 00 00 7c 02 33 c9 40 3d ?? ?? ?? ?? 7c e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StartPage_PVW_2147729418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StartPage.PVW!bit"
        threat_id = "2147729418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StartPage"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TrojanRunTimer" wide //weight: 1
        $x_1_2 = "EventFilter.name = TrojanName & \"_filter\"" wide //weight: 1
        $x_1_3 = "For Each browser In browsersArr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StartPage_RPL_2147821596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StartPage.RPL!MTB"
        threat_id = "2147821596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StartPage"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "haijun" ascii //weight: 1
        $x_1_2 = "www.hao774.com/?90215-06196" ascii //weight: 1
        $x_1_3 = "SHELLEXECUTE" ascii //weight: 1
        $x_1_4 = "REGWRITE" ascii //weight: 1
        $x_1_5 = "Start Page" ascii //weight: 1
        $x_1_6 = "Default_Page_URL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StartPage_NP_2147951208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StartPage.NP!MTB"
        threat_id = "2147951208"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StartPage"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 45 fc 50 8b 45 fc 8d 04 86 50 56 53 e8 f5 fd ff ff 83 c4 14 8b 45 fc 48 a3 90 72 40 00 89 35 94 72 40 00 5e 5b 89 ec}  //weight: 2, accuracy: High
        $x_1_2 = {89 f9 89 f0 31 d2 f7 f1 89 d0 8a 80 00 67 40 00 88 03 8d 43 01 5f 5e 5b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

