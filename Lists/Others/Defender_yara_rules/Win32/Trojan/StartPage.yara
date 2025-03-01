rule Trojan_Win32_Startpage_GY_2147506840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.GY"
        threat_id = "2147506840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "word=%us&tn=leizhen&ie" ascii //weight: 1
        $x_1_2 = {52 61 69 6e 6d 65 74 65 72 2e 6e 6c 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {77 69 6e 67 68 6f 00 00 68 61 6f 6b 61 6e 00 00 62 61 69 64 75 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_HE_2147507516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.HE"
        threat_id = "2147507516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 fa 01 75 07 68 ?? ?? ?? ?? eb 1d 83 fa 03 75 07 68 ?? ?? ?? ?? eb 11 83 fa 04 75 07 68 ?? ?? ?? ?? eb 05}  //weight: 2, accuracy: Low
        $x_1_2 = {67 63 6d 63 79 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = "lexplorer.ini" ascii //weight: 1
        $x_2_4 = {8b 4d 1c 41 8b c1 89 4d 1c 83 f8 18 73 31 68 e8 03 00 00 6a 40}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_KU_2147510666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.KU"
        threat_id = "2147510666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 70 65 6e 20 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 25 45 36 25 46 3d [0-32] 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f 25 36 37 25 36 46 25 32 45 25 36 45 25 36 35 25 37 37 25 36 31 25 36 31 25 32 45 25 36 39 25 36 45 25 36 36 25 36 46 2f 3f 69 3d [0-2] 26 [0-48] 00 6f 70 65 6e 20 fe 81 11 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 00 4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c 20 53 79 73 74 65 6d 20 76 32 2e 34 35 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_KV_2147512701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.KV"
        threat_id = "2147512701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 65 78 70 6c 6f 72 65 2e 65 78 65 20 68 74 74 70 3a 2f 2f 77 77 77 2e 6d 79 31 33 33 2e 6e 65 74 2f 3f 32 00 fd 99 80 00 53 65 46 61 73 74 49 6e 73 74 61 6c 6c 32 5f 33 32 31 38 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 64 39 2e 6e 65 74 2f 63 6f 75 6e 74 6e 65 77 2f 57 72 69 74 65 44 61 74 61 2e 61 73 70 78 3f 69 64 3d fd 8a 80 26 4d 41 43 3d fd 8b 80 26 6d 64 35 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_2147577961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.gen!dll"
        threat_id = "2147577961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{329A624A-1D22-48ae-9576-A02F1EDB1372}" ascii //weight: 1
        $x_1_2 = "9348.cn" ascii //weight: 1
        $x_1_3 = "6700.cn" ascii //weight: 1
        $x_1_4 = "3929.cn" ascii //weight: 1
        $x_1_5 = "2548.cn" ascii //weight: 1
        $x_1_6 = "kzxf.net" ascii //weight: 1
        $x_1_7 = "www.9348.cn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Startpage_2147577961_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.gen!dll"
        threat_id = "2147577961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "600"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "action=\"http://'+domain+'/search.php\" method=get" ascii //weight: 100
        $x_100_2 = "class=rightButton><input type=button onclick=\"Bx();return null;\"" ascii //weight: 100
        $x_100_3 = "formWeb.ww.value=text; Bx();" ascii //weight: 100
        $x_100_4 = "s=escape(formWeb.ww.value);" ascii //weight: 100
        $x_100_5 = {07 00 53 00 50 00 2e 00 48 00 54 00 4d 00 4c}  //weight: 100, accuracy: High
        $x_100_6 = {50 45 00 00 4c 01 02 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 e0 00 0e 21 0b 01 07 0a 00 00 00 00 00 24 00 00 00 00 00 00 00 00 00 00 00 10 00 00}  //weight: 100, accuracy: Low
        $x_100_7 = {3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 6a 61 76 61 73 63 72 69 70 74 3e 0a 20 76 61 72 20 64 6f 6d 61 69 6e 3d 27}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Startpage_C_2147593503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.gen!C"
        threat_id = "2147593503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Start Page" wide //weight: 10
        $x_10_2 = "\\Software\\Microsoft\\Internet Explorer\\Main" wide //weight: 10
        $x_10_3 = "\\registry\\user" wide //weight: 10
        $x_10_4 = "\\SystemRoot" wide //weight: 10
        $x_10_5 = "ntoskrnl.exe" ascii //weight: 10
        $x_10_6 = "KeServiceDescriptorTable" ascii //weight: 10
        $x_10_7 = "ZwSetValueKey" ascii //weight: 10
        $x_10_8 = "ZwWriteFile" ascii //weight: 10
        $x_10_9 = "userinit.exe" ascii //weight: 10
        $x_1_10 = "wwwa.5009.cn" ascii //weight: 1
        $x_1_11 = "wwwb.5009.cn" ascii //weight: 1
        $x_1_12 = "wwwc.5009.cn" ascii //weight: 1
        $x_1_13 = "wwwd.5009.cn" ascii //weight: 1
        $x_1_14 = "wwwe.5009.cn" ascii //weight: 1
        $x_1_15 = "wwwf.5009.cn" ascii //weight: 1
        $x_1_16 = "wwwg.5009.cn" ascii //weight: 1
        $x_1_17 = "www.haol23.net" ascii //weight: 1
        $x_1_18 = "4199.5009.cn" ascii //weight: 1
        $x_10_19 = {8b ec 83 ec 34 56 68 ?? ?? ?? ?? 8d 45 e4 50 ff 15 ?? ?? ?? ?? 8d 45 e4 89 45 d4 8d 45 cc 50 33 f6 68 3f 00 0f 00 8d 45 f0 50 c7 45 cc 18 00 00 00 89 75 d0 c7 45 d8 40 02 00 00 89 75 dc 89 75 e0 ff 15 ?? ?? ?? ?? 85 c0 0f 8c cf 00 00 00 53 8b 1d ?? ?? ?? ?? 57 89 75 ec bf 44 64 6b 20 57 89 75 f4 be 00 02 00 00 56 6a 01 ff d3 85 c0 89 45 fc 0f 84 9b 00 00 00 57 bf 00 04 00 00 57 6a 01 ff d3 33 db 3b c3 89 45 f8 74 7e 56 53 ff 75 fc e8 ?? ?? ?? ?? 83 c4 0c 8d 45 ec 50 56 ff 75 fc 53 53 8b 1d ?? ?? ?? ?? eb 4d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_B_2147593514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.gen!B"
        threat_id = "2147593514"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\dragon" wide //weight: 5
        $x_1_2 = "csrss.exe" wide //weight: 1
        $x_1_3 = "a521.exe" wide //weight: 1
        $x_1_4 = "services.exe" wide //weight: 1
        $x_1_5 = "hublink" wide //weight: 1
        $x_5_6 = "software\\microsoft\\windows\\currentVersion\\run" wide //weight: 5
        $x_5_7 = "software\\Microsoft\\Windows\\CurrentVersion\\Runservices" wide //weight: 5
        $x_3_8 = "win.ini" wide //weight: 3
        $x_5_9 = "software\\Microsoft\\Internet Explorer\\Main" wide //weight: 5
        $x_3_10 = "Start Page" wide //weight: 3
        $x_3_11 = "vb6chs.dll" ascii //weight: 3
        $x_3_12 = "advapi32.dll" ascii //weight: 3
        $x_3_13 = "RegCreateKeyA" ascii //weight: 3
        $x_3_14 = "RegSetValueExA" ascii //weight: 3
        $x_3_15 = "RegisterServiceProcess" ascii //weight: 3
        $x_3_16 = "WritePrivateProfileStringA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 8 of ($x_3_*) and 4 of ($x_1_*))) or
            ((4 of ($x_5_*) and 7 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_5_*) and 8 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_E_2147593663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.gen!E"
        threat_id = "2147593663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Microsoft\\Internet Explorer\\Main" ascii //weight: 10
        $x_5_2 = "\\eplrr9.dll" ascii //weight: 5
        $x_3_3 = "GetSystemDirectoryA" ascii //weight: 3
        $x_3_4 = "pdx.dll" ascii //weight: 3
        $x_1_5 = "Search Page" ascii //weight: 1
        $x_1_6 = "Local Page" ascii //weight: 1
        $x_1_7 = "Start Page" ascii //weight: 1
        $x_1_8 = "[InternetShortcut]" ascii //weight: 1
        $x_1_9 = "URL=%s" ascii //weight: 1
        $x_1_10 = "First Home Page" ascii //weight: 1
        $x_1_11 = "Default_Search_URL" ascii //weight: 1
        $x_1_12 = "Default_Page_URL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_F_2147593664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.gen!F"
        threat_id = "2147593664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 5
        $x_5_2 = "FPUMaskValue" ascii //weight: 5
        $x_5_3 = {68 74 74 70 3a 2f 2f [0-3] 2e 6f 6b 75 6e 69 6f 6e 2e 63 6f 6d 2f 31 2e 74 78 74}  //weight: 5, accuracy: Low
        $x_5_4 = "Start Page" ascii //weight: 5
        $x_5_5 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 5
        $x_5_6 = "0:\\Program Files\\Internet Explorer\\IEXPLORE.EXE" ascii //weight: 5
        $x_1_7 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_8 = "QQQQQQS3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_G_2147594438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.gen!G"
        threat_id = "2147594438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "75"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Start Page" ascii //weight: 10
        $x_10_2 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 10
        $x_10_3 = "%s\\drivers\\etc\\hosts" ascii //weight: 10
        $x_10_4 = "wecxg32.dll" ascii //weight: 10
        $x_10_5 = "{4234f700-cba3-4071-b251-47cb894244cd}" ascii //weight: 10
        $x_10_6 = "InternetOpenUrlA" ascii //weight: 10
        $x_10_7 = "RegSetValueExA" ascii //weight: 10
        $x_1_8 = "zxmsn.dll" ascii //weight: 1
        $x_1_9 = "gupd.dll" ascii //weight: 1
        $x_1_10 = "cidpoq32.dll" ascii //weight: 1
        $x_1_11 = "cidft.dll" ascii //weight: 1
        $x_1_12 = "sdfup.dll" ascii //weight: 1
        $x_1_13 = "xcwer32.dll" ascii //weight: 1
        $x_1_14 = "icvbr.dll" ascii //weight: 1
        $x_1_15 = "icqrt.dll" ascii //weight: 1
        $x_1_16 = "icnfe.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_H_2147594439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.gen!H"
        threat_id = "2147594439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 10
        $x_10_2 = "Start Page" ascii //weight: 10
        $x_5_3 = "about:blank" ascii //weight: 5
        $x_5_4 = "hao123" ascii //weight: 5
        $x_5_5 = "StartServiceA" ascii //weight: 5
        $x_5_6 = "paraudio" ascii //weight: 5
        $x_1_7 = "http://www.kzdh.com/" ascii //weight: 1
        $x_1_8 = "www.265.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_CL_2147596926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.CL"
        threat_id = "2147596926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel\\{871C5380-42A0-1069-A2EA-08002B30309D}" ascii //weight: 1
        $x_1_2 = "Software\\Policies\\Microsoft\\Internet Explorer\\Control Panel\\SecAddSites" ascii //weight: 1
        $x_1_3 = "Software\\Policies\\Microsoft\\Internet Explorer\\Control Panel\\HOMEPAGE" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Internet Explorer\\Main\\Start Page" ascii //weight: 1
        $x_1_5 = "url1=http://www.ooooos.com/" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\pit" ascii //weight: 1
        $x_1_7 = "C:\\Program Files\\Internet Explorer\\IEXPLORE.EXE" ascii //weight: 1
        $x_1_8 = "http://www.xia3.com/" ascii //weight: 1
        $x_1_9 = "\\SVCHOST.EXE" ascii //weight: 1
        $x_1_10 = "krnln.fnr" ascii //weight: 1
        $x_1_11 = "\\seep.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_Win32_Startpage_DB_2147598790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.DB"
        threat_id = "2147598790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel\\{871C5380-42A0-1069-A2EA-08002B30309D}" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\IEXPOLRE" ascii //weight: 1
        $x_1_3 = "http://d.baidu.com/index.php?tn=ooooos_pg" ascii //weight: 1
        $x_1_4 = "http://www.xia3.com" ascii //weight: 1
        $x_1_5 = "http://www.qqye.com" ascii //weight: 1
        $x_1_6 = "[cctv06.com].lnk" ascii //weight: 1
        $x_1_7 = "http://www.cctv06.com" ascii //weight: 1
        $x_1_8 = "http://www.youxiw.com" ascii //weight: 1
        $x_1_9 = "\\kstool.exe" ascii //weight: 1
        $x_1_10 = "http://www.yahuooo.com" ascii //weight: 1
        $x_1_11 = "Software\\Microsoft\\Internet Explorer\\Main\\Start Page" ascii //weight: 1
        $x_1_12 = "Failed to load kernel library!" ascii //weight: 1
        $x_1_13 = "Not found the kernel library!" ascii //weight: 1
        $x_1_14 = "krnln.fne" ascii //weight: 1
        $x_1_15 = "krnln.fnr" ascii //weight: 1
        $x_1_16 = "WTNE / MADE BY E COMPILER - WUTAO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_KD_2147602551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.KD"
        threat_id = "2147602551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "REG ADD \"HKCU\\Software\\Microsoft\\Internet Explorer\\SearchScopes\\{A34587234-AWER-3256-5TY6-12EDERGTY568}\" /V \"URL\" /T REG_SZ /D http://www.mbuscas.com/search.php?q={searchTerms}&pagina=1&rxp=20 /F" ascii //weight: 1
        $x_1_2 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_3 = "GetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_DC_2147612008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.DC"
        threat_id = "2147612008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 3
        $x_3_2 = "www.apeha.ru" ascii //weight: 3
        $x_3_3 = "Start Page" ascii //weight: 3
        $x_3_4 = "RegSetValueExA" ascii //weight: 3
        $x_3_5 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 3
        $x_1_6 = {b9 60 e8 43 00 ba 78 e8 43 00 8b 45 f8 e8 44 fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_DE_2147612685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.DE"
        threat_id = "2147612685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\ClassicStartMenu" wide //weight: 1
        $x_1_2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\Main\\Start Page" wide //weight: 1
        $x_1_3 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_4 = "wscript.shell" wide //weight: 1
        $x_1_5 = "360tray.exe" wide //weight: 1
        $x_1_6 = {40 00 52 00 45 00 47 00 20 00 41 00 44 00 44 00 20 00 48 00 4b 00 45 00 59 00 5f 00 4c 00 4f 00 43 00 41 00 4c 00 5f 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 20 00 2f 00 76 00 20 00 [0-32] 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 53 00 5a 00 20 00 2f 00 64 00 20 00 [0-32] 20 00 2f 00 66 00}  //weight: 1, accuracy: Low
        $x_1_7 = {61 00 74 00 74 00 72 00 69 00 62 00 20 00 2b 00 72 00 20 00 2b 00 73 00 20 00 2b 00 68 00 20 00 [0-32] 20 00 3e 00 6e 00 75 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_DK_2147617484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.DK"
        threat_id = "2147617484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 4d 00 61 00 69 00 6e 00 [0-16] 53 00 74 00 61 00 72 00 74 00 20 00 50 00 61 00 67 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "%SystemRoot%\\system32\\SHELL32.dll,220" wide //weight: 1
        $x_1_3 = "http://420.cn/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_DN_2147618611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.DN"
        threat_id = "2147618611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/affcgi/online.fcgi?%" ascii //weight: 1
        $x_1_2 = "/affiliate/interface3.php?userid=" ascii //weight: 1
        $x_1_3 = {68 74 74 70 3a 2f 2f 00 2f 78 78 6d 6d 32 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = {66 75 63 6b 20 6f 66 66 2c 20 62 75 64 64 79 00 53 6f 66 74 77 61 72 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Startpage_EF_2147622590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.EF"
        threat_id = "2147622590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://about-blank.name" wide //weight: 1
        $x_1_2 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Internet Explorer\\Main\\Start Page" wide //weight: 1
        $x_1_3 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Win" wide //weight: 1
        $x_1_4 = "Winks Instalador\\msngserv.exe" wide //weight: 1
        $x_1_5 = "C:\\windows\\win.exe" wide //weight: 1
        $x_1_6 = {89 0a 8b 4d a8 89 45 ac 83 ec 10 89 4a 04 89 42 08 8b 45 b0 89 42 0c 8b 55 84 8b cc b8 ?? ?? 40 00 6a 02 89 11 68 ?? ?? 40 00 89 71 04 89 41 08 8d 45 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_EJ_2147623555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.EJ"
        threat_id = "2147623555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://tj.key5188.com" ascii //weight: 1
        $x_1_2 = {33 c0 55 68 ?? ?? 40 00 64 ff 30 64 89 20 b8 ?? ?? 40 00 ba ?? ?? 40 00 e8 ?? ?? ff ff 6a 00 68 ?? ?? 40 00 a1 ?? ?? 40 00 e8 ?? ?? ff ff 50 68 ?? ?? 40 00 68 ?? ?? 40 00 6a 00 e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10 68 ?? ?? 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_ZF_2147624046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.ZF"
        threat_id = "2147624046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 74 61 72 74 20 50 61 67 65 00 00 42 75 74 74 6f 6e 00 00 c8 b7 b6 a8 00 00 00 00 23 33 32 37 37 30 00 00 c8 f0 d0 c7 d7 a2 b2 e1 b1 ed bc e0 bf d8 cc e1 ca be 00}  //weight: 10, accuracy: High
        $x_1_2 = "StartServiceCtrlDispatcher OK." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_YR_2147624077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.YR"
        threat_id = "2147624077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 53 65 61 72 63 68 53 63 6f 70 65 73 5c 7b 43 35 43 30 41 37 43 41 2d 44 38 32 30 2d 34 41 45 41 2d 42 33 39 33 2d 41 39 34 45 37 37 31 36 33 30 45 41 7d 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {44 69 73 70 6c 61 79 4e 61 6d 65 [0-10] 68 74 74 70 3a 2f 2f 77 77 77 2e 68 61 33 34 35 2e 63 6f 6d 2f 70 2f 3f 71 3d 7b 73 65 61 72 63 68 54 65 72 6d 73 7d}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 22 [0-15] 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e [0-15] 53 74 61 72 74 20 50 61 67 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_EW_2147625516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.EW"
        threat_id = "2147625516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "explorer.exe,C:\\WINDOWS\\system32\\Winlans.exe" wide //weight: 1
        $x_1_2 = ":redel" wide //weight: 1
        $x_1_3 = "goto redel" wide //weight: 1
        $x_1_4 = "del %0" wide //weight: 1
        $x_1_5 = "HKCR\\lanren\\tihuan" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_EX_2147625578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.EX"
        threat_id = "2147625578"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://soft.c393c.cn/newup3.txt" ascii //weight: 1
        $x_1_2 = "Microsoft\\Internet Explorer\\Quick Launch" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Internet Explorer\\Main\\Start Page" ascii //weight: 1
        $x_1_4 = {7a 68 61 6f [0-1] 2e 6e 65 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_FE_2147628506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.FE"
        threat_id = "2147628506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "plak1.Form1.resources" ascii //weight: 1
        $x_1_2 = "plak1.Properties.Resources.resources" ascii //weight: 1
        $x_2_3 = "C:\\Users\\cnr\\Desktop\\dogukan\\plak1\\plak1\\obj\\Debug\\plak1.pdb" ascii //weight: 2
        $x_1_4 = "Win32_NetworkAdapterConfiguration" wide //weight: 1
        $x_1_5 = "LBLMACID" wide //weight: 1
        $x_1_6 = "start page" wide //weight: 1
        $x_2_7 = "http://www.overidea.com/client/?macid=" wide //weight: 2
        $x_2_8 = "http://www.plak1.com/Google/" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_GD_2147628531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.GD"
        threat_id = "2147628531"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 41 64 76 61 6e 63 65 64 20 49 4e 46 20 53 65 74 75 70 [0-4] ff ff ff ff 07 00 00 00 73 74 72 4c 69 6e 6b 00 ff ff ff ff 14 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 31 31 38 38 2e 63 6f 6d 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "SetLayeredWindowAttributes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_I_2147629460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.gen!I"
        threat_id = "2147629460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 31 33 33 2e 6e 65 74 00 00 ff ff ff ff 29 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 00 00 00 ff ff ff ff 0a 00 00 00 53 74 61 72 74 20 50 61 67 65 00}  //weight: 10, accuracy: High
        $x_10_2 = {69 6d 65 5c 53 50 54 49 50 49 4d 45 52 53 2e 69 6e 69 00}  //weight: 10, accuracy: High
        $x_10_3 = {52 65 67 73 76 72 33 32 2e 65 78 65 20 2f 73 20 00}  //weight: 10, accuracy: High
        $x_1_4 = {43 3a 5c 50 52 4f 47 52 41 7e 31 5c 66 78 36 37 38 54 6f 6f 6c 62 61 72 5c 00 00 00 ff ff ff ff 10 00 00 00 66 78 36 37 38 54 6f 6f 6c 62 61 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {43 3a 5c 50 52 4f 47 52 41 7e 31 5c 59 6f 75 64 61 6f 5c 54 6f 6f 6c 62 61 72 5c 79 64 74 62 76 32 2e 32 33 5c 00 00 00 ff ff ff ff 10 00 00 00 59 6f 64 61 6f 54 6f 6f 6c 62 61 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 3a 5c 50 52 4f 47 52 41 7e 31 5c 59 6f 75 64 61 6f 5c 54 6f 6f 6c 62 61 72 5c 79 64 74 62 76 32 2e 33 5c 00 00 00 00 ff ff ff ff 10 00 00 00 59 6f 64 61 6f 54 6f 6f 6c 62 61 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_GG_2147630082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.GG"
        threat_id = "2147630082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_2 = {53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e [0-16] 53 74 61 72 74 20 50 61 67 65}  //weight: 1, accuracy: Low
        $x_1_3 = "SOFTWARE\\Clients\\StartMenuInternet\\IEXPLORE.EXE\\shell\\Open\\command" ascii //weight: 1
        $x_1_4 = "\\WINDOWS\\system32\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\KasperskyLab" ascii //weight: 1
        $x_1_6 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_GQ_2147630680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.GQ"
        threat_id = "2147630680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 78 36 37 38 54 6f 6f 6c 62 61 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 2e 75 72 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {b9 05 01 00 00 e8 ?? ?? ?? ?? 83 7d e4 00 74 1f 8b 45 e4 e8 ?? ?? ?? ?? 8b 55 e4 80 7c 02 ff 5c 74 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_NZ_2147630908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.NZ"
        threat_id = "2147630908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 4d 00 61 00 69 00 6e 00 5c 00 53 00 74 00 61 00 72 00 74 00 20 00 50 00 61 00 67 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "user_pref(\"browser.startup.homepage\", \"http://www.cherche.us/" wide //weight: 1
        $x_1_3 = "homepage\": \"http://www.cherche.us/" wide //weight: 1
        $x_1_4 = {75 00 72 00 6c 00 73 00 5f 00 74 00 6f 00 5f 00 72 00 65 00 73 00 74 00 6f 00 72 00 65 00 5f 00 6f 00 6e 00 5f 00 73 00 74 00 61 00 72 00 74 00 75 00 70 00 22 00 3a 00 20 00 5b 00 20 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 63 00 68 00 65 00 72 00 63 00 68 00 65 00 2e 00 75 00 73 00 2f 00 22 00 20 00 5d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_GW_2147631475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.GW"
        threat_id = "2147631475"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CLSID\\{871C5380-42A0-1069-A2EA-08002B30309D}\\shell\\OpenHomePage\\Command" ascii //weight: 1
        $x_2_2 = {68 04 00 00 80 6a 00 68 ?? ?? ?? ?? 68 04 00 00 80 6a 00 68 ?? ?? ?? ?? 68 01 03 00 80 6a 00 68 01 00 00 00 68 03 00 00 00 bb a4 06 00 00 e8 ?? ?? ?? ?? 83 c4 28 68 05 00 00 80 6a 00 68 ?? ?? ?? ?? 68 04 00 00 80 6a 00 68 ?? ?? ?? ?? 68 02 00 00 00 bb 6c 02 00 00 e8}  //weight: 2, accuracy: Low
        $x_2_3 = {6a 01 6a 00 68 ?? ?? ?? ?? 52 ff d6 8b 4c 24 1c 8d 44 24 28 50 68 ?? ?? ?? ?? 51 ff d7 6a 00 6a 26 8d 54 24 3c 52 6a 00 ff 15 ?? ?? ?? ?? 8b 84 24 48 03 00 00 50 8d 4c 24 38 51 8d 94 24 40 01 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_GX_2147631509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.GX"
        threat_id = "2147631509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "={searchTerms}&tn=yxdowncn&ie=utf-8" ascii //weight: 1
        $x_1_2 = "baidu,hao123,qq5,go2000,1188,185b" ascii //weight: 1
        $x_1_3 = "{871C5380-42A0-1069-A2EA-08002B30309D}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_HJ_2147631832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.HJ"
        threat_id = "2147631832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 00 00 00 ff ff ff ff 0a 00 00 00 53 74 61 72 74 20 50 61 67 65}  //weight: 1, accuracy: High
        $x_1_2 = "\\Microsoft\\Internet Explorer\\Quick Launch\\" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Advanced INF Setup" ascii //weight: 1
        $x_1_4 = "http://www.baidu.com/s?wd={searchTerms}&tn=yxdowncn&ie=utf-8" ascii //weight: 1
        $x_1_5 = {69 65 5c 00 ff ff ff ff 0c 00 00 00 69 65 78 70 6c 6f 72 65 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_HK_2147631847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.HK"
        threat_id = "2147631847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Internet Explorer\\Niko\\IEXPLORE.EXE" ascii //weight: 1
        $x_1_2 = "\\Internet Explorer\\iexplore.exe %1 h%t%t%p%:%/%/" ascii //weight: 1
        $x_1_3 = "Defaults\\winshutdown.vbs" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "?tn=leizhen" ascii //weight: 1
        $x_1_6 = "deskmate.nls" ascii //weight: 1
        $x_1_7 = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations /v ModRiskFileTypes" ascii //weight: 1
        $x_1_8 = "SOFTWARE\\Microsoft\\Advanced INF Setup" ascii //weight: 1
        $x_1_9 = "gpupdate /force" ascii //weight: 1
        $x_1_10 = "SOFTWARE\\Kingsaft" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Startpage_HN_2147631920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.HN"
        threat_id = "2147631920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 74 61 72 74 20 50 61 67 65 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e}  //weight: 1, accuracy: High
        $x_1_2 = "Accept-Language:zh-cn" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" ascii //weight: 1
        $x_1_4 = "RestrictRun" ascii //weight: 1
        $x_1_5 = "C:\\WINDOWS\\system32\\drivers\\etc\\service3.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_IF_2147633100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.IF"
        threat_id = "2147633100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 0c 8d 0c 02 a1 ?? ?? ?? ?? 8a 04 30 30 01 46 42 3b 54 24 10 7c e1}  //weight: 1, accuracy: Low
        $x_1_2 = "*Internet*.lnk\" /s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_IM_2147633414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.IM"
        threat_id = "2147633414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Microsoft\\Internet Explorer\\Quick Launch" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "tn=leizhen" ascii //weight: 1
        $x_1_5 = "Windows Scripting Host" ascii //weight: 1
        $x_1_6 = "TheWorld.ini" ascii //weight: 1
        $x_1_7 = "\\OpenHomePage\\Command" ascii //weight: 1
        $x_1_8 = {6d 61 69 6e 00 00 00 00 68 6f 6d 65 70 61 67 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Startpage_IP_2147633602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.IP"
        threat_id = "2147633602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Program Files\\Internet Explorer\\iexplore.exe http://" ascii //weight: 1
        $x_1_2 = "}\\shell\\OpenHomePage\\Command\\" ascii //weight: 1
        $x_1_3 = "InternetShortcut" ascii //weight: 1
        $x_1_4 = "$$\\wininit.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_WD_2147634352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.WD"
        threat_id = "2147634352"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SogouExplorer" ascii //weight: 1
        $x_1_2 = "Application Data\\360se\\360SE.ini" ascii //weight: 1
        $x_1_3 = ".776la.com" ascii //weight: 1
        $x_1_4 = "Iese.tmp" ascii //weight: 1
        $x_1_5 = "dh.ad29.com/?id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Startpage_PZ_2147634516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.PZ"
        threat_id = "2147634516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 c9 8a 08 e3 08 80 f1 08 88 08 40 eb f4}  //weight: 2, accuracy: High
        $x_1_2 = "windows\\usp10.dl" ascii //weight: 1
        $x_1_3 = "\\nprotect.sys" ascii //weight: 1
        $x_1_4 = "-seturl" ascii //weight: 1
        $x_1_5 = "stat.php?uid=vegazy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_WG_2147634519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.WG"
        threat_id = "2147634519"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinGames.lnk" ascii //weight: 1
        $x_1_2 = "C:\\Program Files\\WinGames\\bb.tmp" ascii //weight: 1
        $x_1_3 = "C:\\Program Files\\WinGames\\wingames.exe" ascii //weight: 1
        $x_1_4 = "C:\\Program Files\\WinGames\\QvodSetupPlus.exe" ascii //weight: 1
        $x_1_5 = "so1.5k5.net/interface" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Startpage_WH_2147634544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.WH!dll"
        threat_id = "2147634544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".ttkds.com/" ascii //weight: 1
        $x_1_2 = ".9969.net/" ascii //weight: 1
        $x_1_3 = "{7106CBFF-EE71-44F5-8298-A42130BF88C5}" ascii //weight: 1
        $x_1_4 = "regsvr32.exe SuperRepair.dll /s" ascii //weight: 1
        $x_1_5 = "so1.5k5.net/interface" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Startpage_WI_2147634546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.WI"
        threat_id = "2147634546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Internet Explorer.lnk" wide //weight: 1
        $x_1_2 = "www.7802.com" wide //weight: 1
        $x_1_3 = "%HOMEDRIVE%%HOMEPATH%" wide //weight: 1
        $x_1_4 = "\\HideDesktopIcons\\ClassicStartMenu\\{871C5380-42A0-1069-A2EA-08002B30309D}" wide //weight: 1
        $x_1_5 = "\\HideDesktopIcons\\NewStartPanel\\{871C5380-42A0-1069-A2EA-08002B30309D}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_JP_2147635796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.JP"
        threat_id = "2147635796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CLSID\\{871C5380-42A0-1069-A2EA-08002B30309D}\\shell\\OpenHomePage\\Command" ascii //weight: 1
        $x_1_2 = "Microsoft\\Internet Explorer\\Quick Launch" ascii //weight: 1
        $x_1_3 = "GuWS.Run" ascii //weight: 1
        $x_1_4 = "vbhide" ascii //weight: 1
        $x_1_5 = "360se" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_JQ_2147635797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.JQ"
        threat_id = "2147635797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CLSID\\{871C5380-42A0-1069-A2EA-08002B30309D}\\shell\\OpenHomePage\\Command" ascii //weight: 1
        $x_1_2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 73 79 73 [0-2] 6b 65 79 73 2e 64 6c 6c 22}  //weight: 1, accuracy: Low
        $x_1_3 = "www.hao123.com" ascii //weight: 1
        $x_1_4 = "www.9969.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_JU_2147635818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.JU"
        threat_id = "2147635818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CLSID\\{871C5380-42A0-1069-A2EA-08002B30309D}\\shell\\OpenHomePage\\Command" ascii //weight: 1
        $x_1_2 = "Microsoft\\Internet Explorer\\Quick Launch" ascii //weight: 1
        $x_1_3 = {77 69 6e 67 68 6f 00 00 68 61 6f 6b 61 6e 00 00 62 61 69 64 75 00}  //weight: 1, accuracy: High
        $x_1_4 = "start page" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_RF_2147635917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.RF"
        threat_id = "2147635917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f8 01 1b db 43 84 db 75 0a}  //weight: 1, accuracy: High
        $x_1_2 = {d4 da cf df 2e 6c 6e 6b}  //weight: 1, accuracy: High
        $x_2_3 = "www.yxting.cn/" ascii //weight: 2
        $x_2_4 = "gl.2670.com/" ascii //weight: 2
        $x_1_5 = "LookupAccountSidA" ascii //weight: 1
        $x_1_6 = "Files\\Internet Explorer\\iexplore" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_RG_2147635919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.RG"
        threat_id = "2147635919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Start Menu\\Programs\\Startup" ascii //weight: 1
        $x_1_2 = "windows\\sys.cmd" ascii //weight: 1
        $x_1_3 = "objShell.Run" ascii //weight: 1
        $x_1_4 = "/f /v \"Favorites\"" ascii //weight: 1
        $x_1_5 = "09D}\\shell\\OpenHomePage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Startpage_WJ_2147635928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.WJ"
        threat_id = "2147635928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\GameClient.exe" wide //weight: 1
        $x_1_2 = "\\bibibi.exe" wide //weight: 1
        $x_2_3 = "HKEY_CLASSES_ROOT\\CLSID\\{C42EB5A1-0EED-E549-91B0-775852013521}" wide //weight: 2
        $x_2_4 = "cmd.exe /c regedit /s \"C:\\\\QQ.reg\"" wide //weight: 2
        $x_2_5 = "\\haha" wide //weight: 2
        $x_2_6 = "{871C5380-42A0-1069-A2EA-08002B30309D}" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_WK_2147635930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.WK"
        threat_id = "2147635930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Q-$-EXE" ascii //weight: 1
        $x_1_2 = "del %0" ascii //weight: 1
        $x_1_3 = "Q888.dll" ascii //weight: 1
        $x_1_4 = "Q999.dll" ascii //weight: 1
        $x_1_5 = "xlooo.dll" ascii //weight: 1
        $x_1_6 = "xlnnn.dll" ascii //weight: 1
        $x_1_7 = "174.139.2.236/Go.ashx?Mac=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Startpage_WL_2147635931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.WL"
        threat_id = "2147635931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.265.la/?" ascii //weight: 1
        $x_1_2 = "LockPage.EXE" wide //weight: 1
        $x_1_3 = "TTrave~1.exe" ascii //weight: 1
        $x_1_4 = "SogouE~1.exe" ascii //weight: 1
        $x_1_5 = "123456" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_WM_2147635932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.WM"
        threat_id = "2147635932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 39 31 ?? ?? 2e 69 6e 66 6f}  //weight: 1, accuracy: Low
        $x_1_2 = "/c reg add \"HKCU\\Software\\Microsoft\\Internet Explorer\\Main\" /v \"Start Page\" /t REG_SZ /d" ascii //weight: 1
        $x_1_3 = {b0 c1 d3 ce e4 af c0 c0 c6 f7 32 2e 6c 6e 6b}  //weight: 1, accuracy: High
        $x_1_4 = {b5 e7 d3 b0 2e 75 72 6c}  //weight: 1, accuracy: High
        $x_1_5 = {d3 ce cf b7 2e 75 72 6c}  //weight: 1, accuracy: High
        $x_1_6 = {bd a1 bf b5 6d 6d cd f8 2e 75 72 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Startpage_WN_2147635933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.WN"
        threat_id = "2147635933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "file://C:\\Anti-KAV.exe" ascii //weight: 1
        $x_1_2 = {39 31 64 64 2e 69 6e 66 6f 3a 31 31 38 38 2f ?? 2e 68 74 6d 6c 3f 63 69 64 3d}  //weight: 1, accuracy: Low
        $x_1_3 = "300*300http://bff.91dd.info:1188/qq300.htm?" ascii //weight: 1
        $x_1_4 = "|250*220http://bff.91dd.info:1188/gg2.htm?" ascii //weight: 1
        $x_1_5 = "|250*250http://bff.91dd.info:1188/gm.htm?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_JW_2147635937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.JW"
        threat_id = "2147635937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PopAdMutex" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 39 31 ?? ?? 2e 69 6e 66 6f 3a 31 31 38 38 2f ?? 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_3 = "Anti-KAV.exe" ascii //weight: 1
        $x_1_4 = "Internot Explorer.url" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_KG_2147636071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.KG"
        threat_id = "2147636071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\software\\microsoft\\windows\\currentversion\\explorer\\hidedesktopicons" ascii //weight: 1
        $x_1_2 = "{871C5380-42A0-1069-A2EA-08002B30309D}" wide //weight: 1
        $x_1_3 = "HKEY_CLASSES_ROOT\\CLSID\\{C42EB5A1-0EED-E549-91B0-775852013521}\\Shell\\Open(&O)" wide //weight: 1
        $x_1_4 = "http://www.hahayouxi.com" wide //weight: 1
        $x_1_5 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 72 00 65 00 67 00 65 00 64 00 69 00 74 00 20 00 2f 00 73 00 20 00 22 00 43 00 3a 00 5c 00 5c 00 51 00 51 00 [0-8] 2e 00 72 00 65 00 67 00 22 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_KM_2147636212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.KM"
        threat_id = "2147636212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Program Files\\Common Files\\iexplore.exe %1 h%t%t%p:%//%w%w%w." ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Classes\\CLSID\\{e17d4fc0-5564-11d1-83f2-00a0c90dc849}\\Shell\\Open(&O)" ascii //weight: 1
        $x_1_3 = "remove myself faile !" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_KM_2147636212_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.KM"
        threat_id = "2147636212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 4c 24 10 51 6a 00 68 65 04 00 00 53 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8d 04 40 8d 04 80 8d 04 80 8d 04 80 8d 14 80 c1 e2 05 52 ff d5}  //weight: 10, accuracy: Low
        $x_1_2 = "{8856F961-340A-11D0-A96B-00C04FD705A2}" wide //weight: 1
        $x_1_3 = {68 74 74 70 3a 2f 2f 67 67 ?? 2e 38 64 61 6f 2e 69 6e 66 6f}  //weight: 1, accuracy: Low
        $x_1_4 = {b0 c1 d3 ce e4 af c0 c0 c6 f7 32 2e 6c 6e 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_KR_2147636683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.KR"
        threat_id = "2147636683"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 9c 8b ca e8 00 00 00 00 5b 8d 55 bc b8 ?? ?? ?? ?? 52 ff d0 89 45 fc 9d 61 80 7d fc 00 74 06 0f b6 45 fc eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 04 16 8a c8 c0 e9 04 c0 e0 04 0a c8 80 7d ff 00 75 04 c6 45 ff 01 8a 45 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_KR_2147636683_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.KR"
        threat_id = "2147636683"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\RtkSYUdp.exe filldelete  " ascii //weight: 1
        $x_1_2 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 00 00 5c 5c 2e 5c 53 4d 41 52 54 56 53 44 00}  //weight: 1, accuracy: High
        $x_1_3 = "Start Page\"=\"http://www.hae123.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_RH_2147636734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.RH"
        threat_id = "2147636734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@shdoclc.dll,-10241" ascii //weight: 1
        $x_1_2 = "&tid=1&d=%s&uid=%s&t=%s" ascii //weight: 1
        $x_1_3 = "shell32.dll,Control_RunDLL inetcpl.cpl,,0" ascii //weight: 1
        $x_1_4 = {5c 73 68 65 6c 6c 5c ca f4 d0 d4 28 26 52 29 5c 43 6f 6d 6d 61 6e 64}  //weight: 1, accuracy: High
        $x_2_5 = "sex-video-online.com" ascii //weight: 2
        $x_2_6 = "%6s%6y%6s%6t%6e%6m" ascii //weight: 2
        $x_1_7 = "wz4321.com/?system" ascii //weight: 1
        $x_1_8 = "Explorer\\HideDesktopIcons\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_RI_2147636736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.RI!dll"
        threat_id = "2147636736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {99 f7 7d 0c 8b ?? 08 ?? ?? ?? 32 ?? 32 45 14}  //weight: 4, accuracy: Low
        $x_1_2 = {76 d5 83 f8 07 73 d0}  //weight: 1, accuracy: High
        $x_1_3 = {85 c0 74 ed 83 7d ?? 02 75 e7 8b 40 04 33 ?? 66 83 38 2d 0f 94}  //weight: 1, accuracy: Low
        $x_1_4 = "Fexplorer.ex" ascii //weight: 1
        $x_1_5 = "://www.%s/?9" ascii //weight: 1
        $x_1_6 = "WINDOWS\\kswebshield.dl" ascii //weight: 1
        $x_1_7 = "go2000.c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_WO_2147636739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.WO"
        threat_id = "2147636739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "YzDockClass" ascii //weight: 1
        $x_1_2 = "\\MacJie.key" ascii //weight: 1
        $x_1_3 = "ndfhi~.tmp" ascii //weight: 1
        $x_1_4 = "ndfhi.bat" ascii //weight: 1
        $x_1_5 = {63 6d 63 67 2e 64 6c 6c 02 00 5c}  //weight: 1, accuracy: Low
        $x_1_6 = {c9 cf cd f8 b3 e5 c0 cb 09 74 79 70 65 2e 61 70 70 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Startpage_KS_2147637056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.KS"
        threat_id = "2147637056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 65 78 70 6c 6f 72 65 2e 65 78 65 20 68 74 74 70 3a 2f 2f 77 77 77 2e 70 70 32 33 34 35 2e 63 6f 6d 00 fd 99 80 00 53 65 46 61 73 74 49 6e 73 74 61 6c 6c 32 5f 33 32 31 38 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 64 39 2e 6e 65 74 2f 63 6f 75 6e 74 6e 65 77 2f 57 72 69 74 65 44 61 74 61 2e 61 73 70 78 3f 69 64 3d fd 8a 80 26 4d 41 43 3d fd 8b 80 26 6d 64 35 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_KT_2147637058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.KT"
        threat_id = "2147637058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 65 78 70 6c 6f 72 65 2e 65 78 65 20 68 74 74 70 3a 2f 2f 77 77 77 2e 6d 79 31 33 33 2e 6e 65 74 2f 3f 32 00 fd 99 80 00 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 64 39 2e 6e 65 74 2f 63 6f 75 6e 74 6e 65 77 2f 57 72 69 74 65 44 61 74 61 2e 61 73 70 78 3f 69 64 3d fd 8a 80 26 4d 41 43 3d fd 8b 80 26 6d 64 35 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_KW_2147637271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.KW"
        threat_id = "2147637271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "05zw.com/taobao/taobao.html" ascii //weight: 1
        $x_1_2 = {69 65 78 70 6c 6f 72 65 2e 65 78 65 20 68 74 74 70 3a 2f 2f 77 77 77 2e 6d 79 31 33 33 2e 6e 65 74 2f 3f 32 00 fd 99 80}  //weight: 1, accuracy: High
        $x_1_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 64 39 2e 6e 65 74 2f 63 6f 75 6e 74 6e 65 77 2f 57 72 69 74 65 44 61 74 61 2e 61 73 70 78 3f 69 64 3d fd 8a 80 26 4d 41 43 3d fd 8b 80 26 6d 64 35 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_WP_2147637323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.WP"
        threat_id = "2147637323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "91695.com" ascii //weight: 1
        $x_1_2 = "copy \"{win}\\snss1.exe\" \"{win}\\snss.exe\"" ascii //weight: 1
        $x_1_3 = "taskkill /im snss.exe" ascii //weight: 1
        $x_1_4 = "taskkill /im 360se.exe" ascii //weight: 1
        $x_1_5 = "{win}\\ff.bat" ascii //weight: 1
        $x_1_6 = {63 6f 70 79 20 22 7b 77 69 6e 7d 5c 73 6e 73 73 2e 6c 6e 6b 22 20 22 7b 70 66 6d 7d 5c c6 f4 b6 af 5c 73 6e 73 73 2e 6c 6e 6b 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_RK_2147637393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.RK"
        threat_id = "2147637393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Win32Games\\\\url.dll" ascii //weight: 1
        $x_1_2 = "rundll32.exe /c sysurl.dll" ascii //weight: 1
        $x_1_3 = "regsvr32.exe /c syspowerues.dll" ascii //weight: 1
        $x_1_4 = "h%t%t%p%:%/%/%w%w%w.6dudu.%c%o%m%/" ascii //weight: 1
        $x_2_5 = {55 52 4c 2e 64 6c 6c 00 64 6f 73 65 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_RL_2147637395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.RL"
        threat_id = "2147637395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b2 e9 c9 b1 b2 a1 b6 be 2e 75 72 6c}  //weight: 2, accuracy: High
        $x_1_2 = "www.go2000.cn/?1" ascii //weight: 1
        $x_1_3 = "www.leileikuai.cn/welcome.php?tn=" ascii //weight: 1
        $x_1_4 = {fe 02 17 5c c6 f4 b6 af 5c cc da d1 b6 51 51 2e 6c 6e 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_WQ_2147637398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.WQ"
        threat_id = "2147637398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "gouwuke.cn/?" ascii //weight: 1
        $x_1_2 = "haoda123.com.cn" ascii //weight: 1
        $x_1_3 = {5c cd f8 c9 cf b9 ba ce ef 2e 75 72 6c}  //weight: 1, accuracy: High
        $x_1_4 = {71 69 77 6e 6e 61 79 2e 62 61 74 ?? ?? ?? ?? ?? ?? ?? ?? ?? 3a 74 72 79 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 65 6c 20 22 00}  //weight: 1, accuracy: Low
        $x_1_5 = {53 49 44 5c 7b 38 37 31 43 35 33 38 30 2d 34 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 30 2d 31 30 36 39 2d 41 32 45 41 2d 30 38 30 30 32 42 33 30 33 30 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_WR_2147637399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.WR!dll"
        threat_id = "2147637399"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Program Files\\Win32Games\\Internet.vbs" ascii //weight: 1
        $x_1_2 = "C:\\Program Files\\Win32Games\\\\url.dll" ascii //weight: 1
        $x_1_3 = "ws.Run \"rundll32.exe /c sysurl.dll helpme\", 0" ascii //weight: 1
        $x_1_4 = "ws.Run \"regsvr32.exe /c syspowerues.dll /s\", 0" ascii //weight: 1
        $x_1_5 = {2e 69 6e 6b 00 00 00 00 ff ff ff ff 05 00 00 00 78 69 68 61 6f 00 00 00 ff ff ff ff 03 00 00 00 32 78 69 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_WS_2147637430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.WS"
        threat_id = "2147637430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Help\\hdger.xml" ascii //weight: 1
        $x_1_2 = "\\1033\\sda.txt" ascii //weight: 1
        $x_1_3 = ".baiduo.org" ascii //weight: 1
        $x_1_4 = "/1235633.3322.org/Game" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_XA_2147637607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.XA"
        threat_id = "2147637607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Internet Explorer.msm4" ascii //weight: 1
        $x_1_2 = "Love360=4*90+R+ing*360" ascii //weight: 1
        $x_1_3 = ".977dh.com" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Classes\\msn4file\\DefaultIcon" ascii //weight: 1
        $x_1_5 = "{F46E512B-E2AC-4901-97C2-3A35910C0256}" ascii //weight: 1
        $x_1_6 = "\\ComDlls\\1143\\bubhlq.exe\" \"%1\"" ascii //weight: 1
        $x_1_7 = ".92nimm.com/?" ascii //weight: 1
        $x_1_8 = {5c c6 af c1 c1 c3 c0 c3 bc cd bc 2e 75 72 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Startpage_XB_2147637608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.XB"
        threat_id = "2147637608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".22ke.com/?" wide //weight: 1
        $x_1_2 = "%programfiles%\\Internet Explorer\\IEHelp.exe" wide //weight: 1
        $x_1_3 = {5c 00 7b 00 38 00 37 00 31 00 43 00 35 00 33 00 38 00 30 00 2d 00 34 00 32 00 41 00 30 00 2d 00 31 00 30 00 36 00 39 00 2d 00 ?? ?? ?? ?? ?? ?? ?? ?? 41 00 32 00 45 00 41 00 2d 00 30 00 38 00 30 00 30 00 32 00 42 00 33 00 30 00 33 00 30 00 39 00 44 00 7d 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\XiaoHao.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_XC_2147637959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.XC"
        threat_id = "2147637959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://%77%77%77%2e%68%61%6f%6c%32%33%2e%63%63" wide //weight: 1
        $x_1_2 = {33 00 36 00 30 00 73 00 61 00 66 00 65 00 2e 00 65 00 78 00 65 00 ?? ?? ?? ?? ?? ?? 30 00 ?? ?? ?? ?? ?? ?? 33 00 36 00 30 00 73 00 64 00 2e 00 65 00 78 00 65 00 ?? ?? ?? ?? ?? ?? 32 00 ?? ?? ?? ?? ?? ?? 33 00 36 00 30 00 74 00 72 00 61 00 79 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 00 74 00 74 00 2e 00 72 00 65 00 67 00 ?? ?? ?? ?? ?? ?? 43 00 55 00 53 00 54 00 4f 00 4d 00}  //weight: 1, accuracy: Low
        $x_1_4 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 ?? ?? 62 00 61 00 69 00 64 00 75 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_LQ_2147638036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.LQ"
        threat_id = "2147638036"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exn.Write strlnk & \"[g]\" & tmcca" ascii //weight: 1
        $x_1_2 = "fso.copyfile wsh.ExpandEnvironmentStrings(\"%WINDIR%\\system32\\\")&\"wscript.exe\",pathn & \"Ntype.exe\",true" ascii //weight: 1
        $x_1_3 = "Dim fso,wsh,path1,path2,path3,path4,path5,pxth1,pathn,pxgh1,cnm,iename,ienamex,oldpath" ascii //weight: 1
        $x_1_4 = "iename=iename & ienamex" ascii //weight: 1
        $x_1_5 = "iename=\"cao++tian\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Startpage_LS_2147638056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.LS"
        threat_id = "2147638056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 44 65 6e 79 4f 6e 46 69 6c 65 00 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 00 55 52 4c 00 68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 32 30 30 30 2e 63 6e 2f 3f 39 62 31 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 43 6c 65 61 72 4f 6e 46 69 6c 65 00 68 74 74 70 3a 2f 2f 62 75 79 2e 68 61 6f 74 65 2e 63 6f 6d 2f 3f 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 74 65 6d 67 5f 74 6d 70 2e 62 61 74 00 3a 70 70 00 31 33 00 31 30 00 73 6c 65 65 70 20 35 30 30 00 64 65 6c 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_LT_2147638131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.LT"
        threat_id = "2147638131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 43 6c 65 61 72 4f 6e 46 69 6c 65 00 68 74 74 70 3a 2f 2f 77 76 77 2e 6a 73 73 6e 73 2e 63 6f 6d 2f 69 6e 64 65 78 2e 68 74 6d 3f 34 30 32 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 00 55 52 4c 00 68 74 74 70 3a 2f 2f 77 76 77 2e 65 79 75 79 75 2e 63 6f 6d 2f 3f 34 30 32 00}  //weight: 1, accuracy: High
        $x_1_3 = "sp=http://www.ko2233.com/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_LU_2147638135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.LU"
        threat_id = "2147638135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BASEURL= http://www.520560.com" ascii //weight: 2
        $x_1_2 = "IconFile=C:\\Program Files\\Internet Explorer\\iexplore.exe" ascii //weight: 1
        $x_1_3 = "\\Microsoft\\Internet Explorer\\Quick Launch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_LW_2147638301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.LW"
        threat_id = "2147638301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "icwd.dat" ascii //weight: 1
        $x_1_2 = "tbgw.dat" ascii //weight: 1
        $x_1_3 = "temg_tmp.bat" ascii //weight: 1
        $x_1_4 = "Internat Explorar.lnk" ascii //weight: 1
        $x_1_5 = {74 61 73 6b 6b 69 6c 6c 00 2f 66 20 2f 69 6d 20 4b 53 57 65 62 53 68 69 65 6c 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_2_6 = {49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 00 55 52 4c 00 68 74 74 70 3a 2f 2f 62 75 79 2e 68 61 6f 74 65 2e 63 6f 6d 2f 3f 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_XE_2147638317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.XE"
        threat_id = "2147638317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "taskkill /f /im ZhuDongFangyu.exe" wide //weight: 1
        $x_1_2 = "{C42EB5A1-0EED-E549-91B0-153485860016}" wide //weight: 1
        $x_1_3 = "clcount/ip.asp?action=install&mac=" wide //weight: 1
        $x_1_4 = {23 00 53 00 74 00 61 00 72 00 74 00 ?? ?? 23 00 [0-162] 3c 00 45 00 6e 00 64 00 45 00 4f 00 53 00 3e 00 61 00 61 00 61 00 61 00 61 00 61 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_XF_2147638435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.XF"
        threat_id = "2147638435"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dINIA:" ascii //weight: 1
        $x_1_2 = "%s\\228.tmp" ascii //weight: 1
        $x_1_3 = "\\tbhdz.ico" ascii //weight: 1
        $x_1_4 = ".LAITAO.INFO" wide //weight: 1
        $x_1_5 = {25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 ?? ?? ?? ?? 4f 4b ?? ?? 26 70 61 75 69 64 3d ?? 26 6d 73 67 3d ?? ?? ?? 26 74 69 6d 65 3d ?? ?? 25 64 2d 25 64 2d 25 64 5f 25 64 3a 25 64 3a 25 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_XG_2147638558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.XG!dll"
        threat_id = "2147638558"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "{329A624A-1D22-48ae-9576-A02F1EDB1372}" ascii //weight: 1
        $x_1_2 = {25 73 2d 25 64 ?? ?? ?? 6b 73 77 65 62 73 68 69 65 6c 64 2e 64 6c 6c ?? 73 61 66 65 6d 6f 6e 2e 64 6c 6c ?? 55 72 6c 46 69 6c 74 65 72 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {67 6f 32 30 30 30 2e 63 6e ?? ?? ?? 67 6f 32 30 30 30 2e 63 6f 6d ?? ?? 71 71 35 2e 63 6f 6d ?? 31 31 38 38 2e 63 6f 6d ?? ?? ?? ?? 33 36 35 6a 2e 63 6f 6d ?? ?? ?? ?? 37 66 37 66 2e 63 6f 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_XH_2147638559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.XH"
        threat_id = "2147638559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sysinfo.tmp" ascii //weight: 1
        $x_1_2 = "\\rund1l32.exe" ascii //weight: 1
        $x_1_3 = ".goodubai.com/?" ascii //weight: 1
        $x_1_4 = "\\DFFAF1BFC44b01BA1D18186B7F1733" ascii //weight: 1
        $x_1_5 = {5c 64 61 65 6d 6f 6e 2e 65 78 65 ?? 5c 73 79 73 74 65 6d 36 34 2e 2e 5c ?? ?? ?? ?? 5c 73 79 73 74 65 6d 36 34 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_XI_2147638560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.XI!dll"
        threat_id = "2147638560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 35 6c 30 2e 6e 65 74 2f 03 00 67 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {5c cf d4 ca be d7 c0 c3 e6 2e 73 63 66 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 43 6f 6d 6d 61 6e 64 3d 54 6f 67 67 6c 65 44 65 73 6b 74 6f 70 20}  //weight: 1, accuracy: Low
        $x_1_3 = "|Safari.exe|Maxthon.exe|SogouExplorer.exe|TheWorld.exe|TTraveler.exe|360SE.exe|chrome.exe|GreenBrowser.exe|opera.exe|firefox.exe|" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_ME_2147638668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.ME"
        threat_id = "2147638668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Main\" /v \"Start Page\" /d http://cbadenoche.com /f" ascii //weight: 1
        $x_1_2 = "user_pref(\"browser.startup.homepage\", \"http://cbadenoche.com\");" ascii //weight: 1
        $x_1_3 = "del profile.txt" ascii //weight: 1
        $x_1_4 = "for /f %%a in (%txt%) do set n=%%a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Startpage_XJ_2147638751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.XJ!dll"
        threat_id = "2147638751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".vol777.com/?" ascii //weight: 1
        $x_1_2 = {42 53 42 2e 65 78 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? 61 75 74 6f 72 75 6e 2e 69 6e 66 ?? ?? ?? ?? ?? ?? ?? ?? ?? 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 42 53 42 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {00 5c b8 c4 b1 e4 c4 e3 b5 c4 d2 bb c9 fa 2e 75 72 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_XH_2147638795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.XH!dll"
        threat_id = "2147638795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".dh005.com/?" ascii //weight: 1
        $x_1_2 = "2..\\..\\Program Files\\I" wide //weight: 1
        $x_1_3 = {39 37 37 64 68 2e 63 6f 6d ?? ?? ?? 35 39 38 2e 6e 65 74 ?? 32 31 31 64 68 2e 63 6f 6d ?? ?? ?? 39 33 36 35 2e 69 6e 66 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_MI_2147638847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.MI"
        threat_id = "2147638847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 00 48 69 64 65 46 69 6c 65 45 78 74}  //weight: 10, accuracy: High
        $x_10_2 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 61 74 20 45 78 70 6c 6f 72 61 72 5c [0-8] 2e 6c 6e 6b}  //weight: 10, accuracy: Low
        $x_10_3 = {5c 49 6e 74 65 72 6e 61 74 20 45 78 70 6c 6f 72 61 72 22 20 2b 73 00 6f 70 65 6e 20 61 74 74 72 69 62}  //weight: 10, accuracy: High
        $x_1_4 = "http://buy.haote.com/?" ascii //weight: 1
        $x_1_5 = "http://www.go2000.cn/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_MJ_2147638864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.MJ"
        threat_id = "2147638864"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "route -p  add 122.225." ascii //weight: 1
        $x_1_2 = "route -p  add 218.77.10." ascii //weight: 1
        $x_1_3 = "route -p  add 61.160.210." ascii //weight: 1
        $x_1_4 = {6f 70 65 6e 00 68 74 74 70 3a 2f 2f 77 77 76 2e 64 69 79 6f 75 2e 6e 65 74 2f}  //weight: 1, accuracy: High
        $x_1_5 = {55 52 4c 00 68 74 74 70 3a 2f 2f 77 77 76 2e 63 61 6f 6b 6f 6e 67 2e 63 6f 6d 2f}  //weight: 1, accuracy: High
        $x_1_6 = "ping 127.0.0.1 -n 30 & shutdown -r -t 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Startpage_MM_2147639014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.MM"
        threat_id = "2147639014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 00 6c 00 6c 00 61 00 3a 00 65 00 6e 00 2d 00 55 00 53 00 3a 00 6f 00 66 00 66 00 69 00 63 00 69 00 61 00 6c 00 00 00 00 00 1e 00 00 00 73 00 74 00 61 00 72 00 74 00 73 00 69 00 74 00 65 00 2e 00 63 00 6f 00 2e 00 6e 00 72 00}  //weight: 1, accuracy: High
        $x_1_2 = "replStartPage.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_XK_2147639084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.XK!dll"
        threat_id = "2147639084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".6dudu.com" ascii //weight: 1
        $x_1_2 = "//122.224.9.113:8022/Insertbz.aspx?" ascii //weight: 1
        $x_1_3 = {5c 73 6f 66 74 70 72 6f 2e 64 6c 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 62 6f 6f 74 69 6e 73 74 61 6c 6c 2e 67 69 66 ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 6a 65 63 74 2e 76 62 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_XL_2147639085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.XL"
        threat_id = "2147639085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "g.freeshipin.info:1188/" ascii //weight: 1
        $x_1_2 = "facai.jiankangmm.com/" ascii //weight: 1
        $x_1_3 = {00 bd a1 bf b5 6d 6d cd f8 00}  //weight: 1, accuracy: High
        $x_1_4 = {7b 45 33 43 31 42 43 37 30 2d 31 36 30 37 2d 34 33 42 44 2d 41 30 35 35 2d 41 43 42 34 42 46 38 44 42 41 ?? ?? 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_XM_2147639086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.XM"
        threat_id = "2147639086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qwxyx.com/" wide //weight: 1
        $x_1_2 = "mmtp5.info/" wide //weight: 1
        $x_1_3 = {c4 e3 d5 fd d4 da bd f8 d0 d0 b0 b2 d7 b0 c9 ab c7 e9 b5 e7 d3 b0 b2 a5 b7 c5 c6 f7 b5 da d2 bb b2 bd}  //weight: 1, accuracy: High
        $x_1_4 = {35 00 39 00 36 00 38 00 38 00 5c 00 56 00 42 00 ad 64 3e 65 68 56 5c 00 e5 5d 0b 7a 31 00 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_XO_2147639491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.XO"
        threat_id = "2147639491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".2345.com" ascii //weight: 1
        $x_1_2 = ".baiduo.org/" ascii //weight: 1
        $x_1_3 = {73 5c 6b 62 [0-9] 2e 6c 6f 67}  //weight: 1, accuracy: Low
        $x_1_4 = "stat.wamme.cn/C8C/gl/cnzz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_RM_2147639599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.RM"
        threat_id = "2147639599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 6a 0c ?? e8 ?? ?? ?? ?? 6a 64 e8 ?? ?? ?? ?? 6a 00 6a 0d 68 00 01 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = {00 51 2d 24 2d 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\HideDesktopIcons\\ClassicStartMenu" ascii //weight: 1
        $x_1_4 = "http://www.lele444.com/?" ascii //weight: 1
        $x_1_5 = "URL=http://888.qq2233.com/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_MR_2147639752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.MR"
        threat_id = "2147639752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 08 80 f9 ff 75 0e 80 78 01 25 75 08 8b 40 02 8b 00 c2 ?? 00 80 f9 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 04 8b 54 24 08 2b d0 83 e9 05 83 ea 05 [0-1] c6 00 e9 89 50 01}  //weight: 1, accuracy: Low
        $x_1_3 = "http://www.9688.la/?" wide //weight: 1
        $x_1_4 = "360se.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_MV_2147640663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.MV"
        threat_id = "2147640663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4b 57 59 2e 50 72 6f 74 65 63 74 65 64 2e 4e 6f 77 2e 00}  //weight: 2, accuracy: High
        $x_2_2 = {4e 65 77 20 57 69 6e 64 6f 77 73 5c 41 6c 6c 6f 77 5c 2a 2e [0-32] 2e 63 63}  //weight: 2, accuracy: Low
        $x_1_3 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {4d 61 69 6e 5c 53 74 61 72 74 20 50 61 67 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_MW_2147640664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.MW"
        threat_id = "2147640664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6a 00 6a 00 6a 00 68 04 00 00 80 6a 00 68 ?? ?? ?? ?? 68 01 03 00 80 6a 00 68 04 00 00 00 68 03 00 00 00 bb ?? ?? ?? ?? e8}  //weight: 3, accuracy: Low
        $x_1_2 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3\\1400" ascii //weight: 1
        $x_1_3 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Internet Explorer\\Main\\" ascii //weight: 1
        $x_1_5 = "Software\\Super-EC\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_XQ_2147641109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.XQ"
        threat_id = "2147641109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".22qi.com/taobao.html" ascii //weight: 1
        $x_1_2 = "aHR0cDovL3d3dy4yMjNsYS5jb20" ascii //weight: 1
        $x_1_3 = "aHR0cDovL3d3dy4yMnFpLmNvbS90YW9iYW8uaHRtbA==" ascii //weight: 1
        $x_1_4 = {25 b0 ae 25 b0 ae 25 c6 e6 25 cd f8 25 d6 b7 25 b5 bc 25 ba bd 5b 25 57 77 25}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_YD_2147641805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.YD"
        threat_id = "2147641805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[InternetShortcut]" ascii //weight: 1
        $x_1_2 = "BASEURL=http://so.5l0.net" ascii //weight: 1
        $x_1_3 = "IconFile=explorer.exe,3" ascii //weight: 1
        $x_1_4 = "iexplore.exe|360SE.exe|Maxthon.exe" ascii //weight: 1
        $x_1_5 = "\\Internet Explorer\\Main\\Start Page" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_NA_2147641950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.NA"
        threat_id = "2147641950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sp=http://www.8808.net.cn" ascii //weight: 1
        $x_1_2 = {31 2c 33 36 30 2e 63 6f 6d 0d 0a 31 2c 62 62 73 2e 33 36 30 2e 63 6e 0d 0a 31 2c 68 65 6c 70 2e 33 36 30 2e 63 6e 0d 0a 31 2c 33 39 33 32 2e 63 6f 6d 0d 0a 31 2c 32 35 34 38 2e 63 6e 0d 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_L_2147641954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.gen!L"
        threat_id = "2147641954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "^18^30^30^26^38^39^39^3" wide //weight: 3
        $x_3_2 = "cmd.exe /c regedit /s c:\\reg.reg" wide //weight: 3
        $x_3_3 = ".RegWrite(\"HKEY_CLASSES_ROOT\\\\CLSID\\\\{e17d4fc0-5564-11d1-83f2-00a0c90dc849}\\\\Shell\\\\\"" wide //weight: 3
        $x_3_4 = "Intelnet Explorer" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_NM_2147642002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.NM"
        threat_id = "2147642002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 49 6e 74 65 72 6e 61 74 20 45 78 70 6c 6f 72 61 72 5c 74 61 72 67 65 74 2e 6c 6e 6b 00 68 74 74 70 3a 2f 2f 77 77 77 2e 70 70 34 30 30 30 2e 63 6f 6d 00 fe 81 11 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 00 6f 70 65 6e 00 63 6d 64 2e 65 78 65 00 2f 63 20 6d 6f 76 65 20 22}  //weight: 1, accuracy: High
        $x_1_2 = {2e 6c 6e 6b 00 68 74 74 70 3a 2f 2f 62 75 79 2e 68 61 6f 74 65 2e 63 6f 6d 2f 3f 00 fe 24 24 5c 74 62 67 77 2e 69 63 6f 00 fd 99 80 5c 74 65 6d 70 5f 74 6d 70 2e 62 61 74}  //weight: 1, accuracy: High
        $x_1_3 = {64 65 6c 20 22 fd 97 80 5c fd 9c 80 22 00 69 66 20 65 78 69 73 74 20 20 20 22 fd 97 80 5c fd 9c 80 22 20 20 20 67 6f 74 6f 20 20 20 70 70 00 64 65 6c 20 25 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_AEI_2147642055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.AEI"
        threat_id = "2147642055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/Insertbz.aspx?mci=" ascii //weight: 2
        $x_2_2 = "firsturl" ascii //weight: 2
        $x_2_3 = "ServerID" ascii //weight: 2
        $x_1_4 = "\\winmsagent\\" ascii //weight: 1
        $x_1_5 = "\\elnk.lnk" ascii //weight: 1
        $x_1_6 = "Config.ini" ascii //weight: 1
        $x_1_7 = "winrun.ico" ascii //weight: 1
        $x_1_8 = "winms32.pcu" ascii //weight: 1
        $x_1_9 = "erun.fzx" ascii //weight: 1
        $x_1_10 = "setupweb.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_NO_2147642143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.NO"
        threat_id = "2147642143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 61 74 20 45 78 70 6c 6f 72 65 72 5c 74 61 72 67 65 74 2e 6c 6e 6b 00 68 74 74 70 3a 2f 2f 77 77 77 2e 74 74 32 36 35 2e 6e 65 74 2f 00 fe 81 11 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 00 6f 70 65 6e 00 61 74 74 72 69 62 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 65 6c 20 22 fd 97 80 5c fd 9c 80 22 00 69 66 20 65 78 69 73 74 20 20 20 22 fd 97 80 5c fd 9c 80 22 20 20 20 67 6f 74 6f 20 20 20 70 70 00 64 65 6c 20 25 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_ACC_2147642221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.ACC!dll"
        threat_id = "2147642221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "aaa234.com" ascii //weight: 1
        $x_1_2 = ".sb173.com/?" ascii //weight: 1
        $x_1_3 = ".game1122.com/?" ascii //weight: 1
        $x_1_4 = {63 3a 5c 66 77 65 2e 6c 6f 67 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 79 79 79 79 6d 6d 64 64 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 3a 5c 66 6a 65 69 2e 6c 6f 67}  //weight: 1, accuracy: Low
        $x_1_5 = {6e 65 74 32 38 37 2e 63 6e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 77 7a 31 31 32 32 2e 63 6f 6d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 71 71 31 39 34 39 2e 6e 65 74}  //weight: 1, accuracy: Low
        $x_1_6 = {56 61 67 61 61 cd db b8 c2 bb ad ca b1 b4 fa 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_OD_2147642342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.OD"
        threat_id = "2147642342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 4d 69 63 72 6f 73 6f 66 74 25 53 5c [0-2] 49 6e 74 65 72 6e 61 74 20 20 45 78 70 6c 6f 72 65 72}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 4d 69 63 72 6f 73 6f 66 74 [0-8] 5c [0-16] 49 6e 74 65 72 6e 65 74 20 20 45 78 70 6c 6f 72 61 72}  //weight: 1, accuracy: Low
        $x_5_3 = "Shell32::SHChangeNotify(i 0x8000000, i 0, i 0, i 0)" ascii //weight: 5
        $x_5_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\360" ascii //weight: 5
        $x_1_5 = "http://buy.haote.com/?" ascii //weight: 1
        $x_1_6 = "http://www.pp1234.net/" ascii //weight: 1
        $x_1_7 = "http://www.my8899.com/" ascii //weight: 1
        $x_1_8 = {30 78 31 33 33 65 63 32 30 00 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_AEJ_2147642546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.AEJ"
        threat_id = "2147642546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ".k969.com" wide //weight: 3
        $x_1_2 = "-ba4f-00a0c91eedba}\\Shell\\Start\\Command\\" wide //weight: 1
        $x_1_3 = "\\iexplore.exe\" http://" wide //weight: 1
        $x_1_4 = "lore.exe,-32528" wide //weight: 1
        $x_1_5 = "\\Desktop\\NameSpace\\{1f4de370-d627-11d1" wide //weight: 1
        $x_1_6 = "a}\\LocalizedString" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_AEL_2147642621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.AEL"
        threat_id = "2147642621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "www.xihao.net/033/taobao.html" ascii //weight: 2
        $x_1_2 = {5c d7 c0 c3 e6 5c cc d4 b1 a6 2d cc d8 c2 f4 2e}  //weight: 1, accuracy: High
        $x_1_3 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 53 74 61 72 74 20 50 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "hook.dll" ascii //weight: 1
        $x_1_6 = "taobao.ico'" ascii //weight: 1
        $x_1_7 = "\\lvegned\\config.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_AEL_2147642621_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.AEL"
        threat_id = "2147642621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Tencent\\TencentTraveler\\100\\favicon" ascii //weight: 2
        $x_2_2 = "\\SogouExplorer\\FavIcon" ascii //weight: 2
        $x_1_3 = "Favorite2.dat" ascii //weight: 1
        $x_1_4 = "navinfo.db" ascii //weight: 1
        $x_1_5 = "http_www.97796.cn_80_fav.ico" ascii //weight: 1
        $x_1_6 = "www.2548.cn_favicon.ico" ascii //weight: 1
        $x_1_7 = "http://www.2548.cn/?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_ACD_2147642698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.ACD!dll"
        threat_id = "2147642698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".779dh.com/?" ascii //weight: 1
        $x_1_2 = ".v258.net/list/list" ascii //weight: 1
        $x_1_3 = ".v921.com/?" ascii //weight: 1
        $x_1_4 = "rundll32.js" ascii //weight: 1
        $x_1_5 = "219.141.119.100:880/?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_ACG_2147642834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.ACG!dll"
        threat_id = "2147642834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "F450EA5FC691BD8DB78C8A9C62" ascii //weight: 1
        $x_1_2 = {2e 6f 6b 67 61 6d 65 64 6f 77 6e 2e 63 6e 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 68 74 6d 6c 3f}  //weight: 1, accuracy: Low
        $x_1_3 = {56 61 67 61 61 cd db b8 c2 bb ad ca b1 b4 fa 00}  //weight: 1, accuracy: High
        $x_1_4 = {46 3a 5c b9 e3 b8 e6 5c b5 bc ba bd 31 30 30 38 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_OF_2147642890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.OF"
        threat_id = "2147642890"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WINDOWS\\system32\\drivers\\etc\\service" ascii //weight: 1
        $x_1_2 = "Program Files\\startup" ascii //weight: 1
        $x_1_3 = {c7 44 24 04 94 00 00 00 ff 15 ?? ?? ?? ?? 83 7c 24 10 02 75 0c 83 7c 24 04 05 b8 ?? ?? ?? ?? 73 05 b8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_OG_2147642929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.OG"
        threat_id = "2147642929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 00 53 74 61 72 74 20 50 61 67 65 00 68 74 74 70 3a 2f 2f 77 77 77 2e 68 61 6f 31 32 33 2e 63 6f 6d 2f 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 6d 34 30 30 30 2e 63 6e 2f 3f 30 [0-8] 00 31 30 32 00 68 74 74 70 3a 2f 2f 77 77 77 2e 68 75 68 61 77 61 6e 67 2e 63 6f 6d 2f 3f 76 30}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 49 6e 74 65 72 6e 61 74 20 45 78 6c 70 6f 72 65 72 5c 74 61 72 67 65 74 2e 6c 6e 6b 00 31 30 31 00 68 74 74 70 3a 2f 2f 77 77 77 2e [0-8] 30 30 30 2e 63 6e 2f 3f 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_OH_2147643128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.OH"
        threat_id = "2147643128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "rundll32 \"C:\\Program Files\\Win32Games\\URL.dll\" doset" ascii //weight: 5
        $x_4_2 = "http://so1.5k5.net/interface?action=install&p=" ascii //weight: 4
        $x_4_3 = "regsvr32 syspowerues.dll /s" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_ACH_2147643238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.ACH"
        threat_id = "2147643238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "c:\\fjeiof1j.log" ascii //weight: 1
        $x_1_2 = "{3E4189C8-FF40-43A4-AF21-D41A5A4EE9F4}" ascii //weight: 1
        $x_1_3 = "52D367B16EBB5EBA7A80B645CE2CF338C85CA27EC351AF7C" ascii //weight: 1
        $x_1_4 = "/wz1949.com/Youdao.dll" ascii //weight: 1
        $x_1_5 = {2f 77 7a 31 31 32 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 63 6f 6d 2f 59 6f 75 64 61 6f 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_OL_2147644301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.OL"
        threat_id = "2147644301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".vbp" wide //weight: 1
        $x_1_2 = "2c49f800-c2dd-11cf-9ad6-0080c7e7b78d" wide //weight: 1
        $x_1_3 = "2670635F6164693D" wide //weight: 1
        $x_1_4 = "Hijack This" wide //weight: 1
        $x_1_5 = "757365725F7072656628" wide //weight: 1
        $x_1_6 = {69 00 6e 00 6e 00 65 00 72 00 48 00 54 00 4d 00 4c 00 [0-8] 34 00 38 00 34 00 42 00 34 00 35 00 35 00 39 00 35 00 46 00 34 00 33 00 35 00 35 00 35 00 32 00 35 00 32 00 34 00 35 00 34 00 45 00 35 00 34 00 35 00 46 00 35 00 35 00 35 00 33 00 34 00 35 00 35 00 32 00}  //weight: 1, accuracy: Low
        $x_1_7 = "UDPFlood" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Startpage_AEN_2147644348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.AEN"
        threat_id = "2147644348"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 49 6e 74 65 72 6e 61 74 [0-4] 45 78 70 6c 6f 72 65 72 2e 6f 67 63 22 20 (2b 68|2b 72)}  //weight: 1, accuracy: Low
        $x_1_2 = {7b 30 41 46 41 43 45 44 31 2d 45 38 32 38 2d 31 31 44 31 2d 39 31 38 37 2d 42 35 33 32 46 31 45 39 35 37 35 44 7d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-15] 5c 44 65 73 6b 74 6f 70 2e 69 6e 69 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-15] 5c 74 61 72 67 65 74 2e 6c 6e 6b 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 55 6e 69 6e 73 74 61 6c 6c 5c 33 36 30 b0 b2 c8 ab ce c0 ca bf 00 44 69 73 70 6c 61 79 56 65 72 73 69 6f 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_AFD_2147645018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.AFD"
        threat_id = "2147645018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 74 65 70 22 20 2f 50 20 45 76 65 72 79 6f 6e 65 3a 52 00 fe 25 25 5c 63 6d 64 2e 65 78 65 20 2f 63 20 65 63 68 6f 20 59 7c 20 63 61 63 6c 73 20 22}  //weight: 1, accuracy: High
        $x_1_2 = "http://%77%77%77%2E%65%7A%31%37%33%2E%63%6F%6D/taobao/" ascii //weight: 1
        $x_1_3 = "http://%79%6F%75%78%31%2E%63%6F%6D/?" ascii //weight: 1
        $x_1_4 = {5c c1 b4 bd d3 5c d0 a1 d3 ce cf b7 2e 75 72 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c c1 b4 bd d3 5c cc d4 b1 a6 cd f8 2e 75 72 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_PN_2147645247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.PN"
        threat_id = "2147645247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "user_pref(%cbrowser.startup.homepage" ascii //weight: 1
        $x_1_2 = "mozilla\\firefox\\profiles\\*" ascii //weight: 1
        $x_1_3 = {ff 74 24 20 ff 15 ?? ?? ?? ?? ff 74 24 0c ff 15 ?? ?? ?? ?? 83 c3 04 8b c3 39 3b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_OQ_2147645734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.OQ"
        threat_id = "2147645734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\WebNav.vbp" wide //weight: 1
        $x_1_2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\Main\\Start Page" wide //weight: 1
        $x_1_3 = "wscript.shell" wide //weight: 1
        $x_1_4 = "c:\\windows\\ime\\d.vbs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_QF_2147646761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.QF"
        threat_id = "2147646761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://www.hao123.com/indexk.htm" ascii //weight: 2
        $x_3_2 = "\\Internet Exlporer" ascii //weight: 3
        $x_3_3 = ".icw\"\"\",0" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_QJ_2147647434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.QJ"
        threat_id = "2147647434"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Clsmn.exe|wxsyncli.exe|CltSrv.exe|WxLink.exe|wxLkExe.exe|wxsyupd.exe|" wide //weight: 3
        $x_4_2 = "]={360tray.exe}{ZhuDongFangYu.exe}{360safe.exe}" wide //weight: 4
        $x_4_3 = "|[NOD32]={ekrn.exe}{nod32krn.exe}{egui.exe}" wide //weight: 4
        $x_2_4 = "mStrEnDe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_QK_2147647595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.QK"
        threat_id = "2147647595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "\\Internat Exlporer.lnk\" /y" ascii //weight: 4
        $x_4_2 = "oUrlLink.TargetPath = \"http://www.yuyu.com/?fav2\"" ascii //weight: 4
        $x_3_3 = "WSHShell.SendKeys \"{F5}\"" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_AFZ_2147648086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.AFZ"
        threat_id = "2147648086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Film.ico" ascii //weight: 1
        $x_1_2 = "\\meiv.ico" ascii //weight: 1
        $x_1_3 = "\\Beauty.ico" ascii //weight: 1
        $x_2_4 = {33 36 30 73 64 2e 65 78 65 00 33 36 30 74 72 61 79 2e 65 78 65 00 51 51 44 6f 63 74 6f 72 52 74 70 2e 65 78 65 00 52 61 76 2e 65 78 65 00 77 78 43 6c 74 41 69 64 2e 65 78 65 00 61 76 70 2e 65 78 65 00 6b 77 73 74 72 61 79 2e 65 78 65}  //weight: 2, accuracy: High
        $x_2_5 = {65 63 68 6f 20 79 7c 20 63 61 63 6c 73 20 22 [0-21] 2e 75 72 6c 22 [0-4] 2f 70 20 65 76 65 72 79 6f 6e 65 3a 66}  //weight: 2, accuracy: Low
        $x_2_6 = {5c 6b 77 73 2e 69 6e 69 22 [0-4] 2b 52 20 2b 53}  //weight: 2, accuracy: Low
        $x_2_7 = {5c 6b 77 73 2e 69 6e 69 22 [0-4] 2f 70 20 65 76 65 72 79 6f 6e 65 3a 52}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_QQ_2147648118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.QQ"
        threat_id = "2147648118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 7b 65 31 37 64 34 66 63 30 2d 35 35 36 34 2d 31 31 64 31 2d 38 33 66 32 2d 30 30 61 30 63 39 30 64 63 38 34 39 7d 5c 73 68 65 6c 6c 5c c6 f4 b6 af 49 6e 74 65 72 6e 65 74}  //weight: 1, accuracy: High
        $x_1_2 = "Rundll32.exe Shell32.dll,Control_RunDLL Inetcpl.cpl" ascii //weight: 1
        $x_1_3 = {5c 53 68 65 6c 6c 46 6f 6c 64 65 72 00 48 69 64 65 4f 6e 44 65 73 6b 74 6f 70 50 65 72 55 73 65 72 00 41 74 74 72 69 62 75 74 65 73 00 30 78 30 30 30 30 30 30 30 30}  //weight: 1, accuracy: High
        $x_1_4 = {5c 41 64 76 61 6e 63 65 64 00 48 69 64 64 65 6e 00 30 78 30 30 30 30 30 30 30 32}  //weight: 1, accuracy: High
        $x_1_5 = {5c 48 69 64 65 44 65 73 6b 74 6f 70 49 63 6f 6e 73 00 43 6c 61 73 73 69 63 53 74 61 72 74 4d 65 6e 75 00 30 78 30 30 30 30 30 30 30 31}  //weight: 1, accuracy: High
        $x_1_6 = {5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 00 4e 6f 49 6e 74 65 72 6e 65 74 49 63 6f 6e}  //weight: 1, accuracy: High
        $x_1_7 = "shell32.dll::SHChangeNotify(l, l, i, i) v (0x08000000, 0, 0, 0)" ascii //weight: 1
        $x_1_8 = {43 61 6c 6c 00 6f 70 65 6e 00 68 74 74 70 3a 2f 2f 77 77 77 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Startpage_RR_2147650776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.RR"
        threat_id = "2147650776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mapping_hk_cntr_" ascii //weight: 2
        $x_3_2 = "~jake1980" ascii //weight: 3
        $x_2_3 = "jsconsole.dll" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_RS_2147650843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.RS"
        threat_id = "2147650843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2a d8 32 5c 24 ?? 8a 44 14 ?? 88 9c 14 ?? ?? 00 00 42 88 44 24 ?? 3a c1 75 de 4d 00 88 8c 14 ?? ?? 00 00 88 44 24 ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? 88 4c 24 ?? 33 d2 88 44 24 ?? 8d 49 00 8a c2 b3 ?? f6 eb b3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_SE_2147651683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.SE"
        threat_id = "2147651683"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 61 62 6c 65 64 00 68 6f 74 54 72 61 63 6b 69 6e 67 00 4d 75 6c 74 69 53 65 6c 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {8d 4d bc e9 ?? ?? ?? ?? ff d7 8b d0 8d 8d 2c fe ff ff e9 ?? ?? ?? ?? 89 8d 34 fb ff ff e9 ?? ?? ?? ?? 8b 48 0c 8b 85 34 fb ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {88 04 3a 8b 45 dc e9 ?? ?? ?? ?? 8d 8d 30 ff ff ff ff d6 8b 95 78 fc ff ff e9 ?? ?? ?? ?? 8d 55 ec 6a 01 52 56 e9}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 00 6a 01 6a 01 8d 85 ec fd ff ff 6a 00 50 6a 10 68 80 08 00 00 ff 15 ?? ?? ?? ?? 8b 4d 98 8b 85 ec fd ff ff 83 c1 04 c7 85 dc fd ff ff ?? ?? ?? ?? 89 8d e4 fd ff ff 8b 48 14 c1 e1 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Startpage_SN_2147652173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.SN"
        threat_id = "2147652173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SetDefaultKK" ascii //weight: 2
        $x_3_2 = "Internet Exp1orer.lnk" wide //weight: 3
        $x_2_3 = "CmdGetSign" ascii //weight: 2
        $x_2_4 = "MDLGlobal" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_SQ_2147652769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.SQ"
        threat_id = "2147652769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 08 40 84 c9 75 [0-5] 2b c2 50 [0-4] 68 ?? ?? ?? ?? 6a 01 56 68 ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {68 57 00 07 80 e8 ?? ?? ?? ?? 55 8b 6c ?? ?? 56 55 53 e8 ?? ?? ?? ?? 8b f0 8b 07 8b 50 f8 83 e8 10}  //weight: 1, accuracy: Low
        $x_1_3 = "ilc.nbz.co.kr/install.asp?id=186&mac=%s" ascii //weight: 1
        $x_1_4 = "diskmania.co.kr/program/yahoo_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_M_2147653202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.gen!M"
        threat_id = "2147653202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 80 41 42 00 50 8b cf e8 5d 54 01 00 8b 8e dc 00 00 00 68 7c 41 42 00 e8 87 5e 01 00 8b 8e dc 00 00 00 68 78 41 42 00 e8 77 5e 01 00 8b 8e dc 00 00 00 68 78 41 42 00 e8 67 5e 01 00 8b 8e dc 00 00 00}  //weight: 1, accuracy: High
        $x_2_2 = "TheWorld.ini" ascii //weight: 2
        $x_2_3 = "rr55.com/?zz" ascii //weight: 2
        $x_2_4 = "go2000.cn/?zz" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_SS_2147653244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.SS"
        threat_id = "2147653244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "http://78.soupay.com/plugin/g.asp?id=" wide //weight: 4
        $x_3_2 = "\\Explorer\\HideDesktopIcons\\NewStartPanel\\{871C5380-42A0-1069-A2EA-08002B30309D}" wide //weight: 3
        $x_4_3 = "Maxthon.exe,TheWorld.exe,IEXPLORE.EXE,FirefoxPortable.exe,firefox.exe,360Start.exe" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_SU_2147653716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.SU"
        threat_id = "2147653716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "360Safetray" wide //weight: 2
        $x_3_2 = "Adobe\\something.ini" wide //weight: 3
        $x_2_3 = "SogouExplorer\\Config.xml" ascii //weight: 2
        $x_2_4 = "HijackIE" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_SW_2147653977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.SW"
        threat_id = "2147653977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 4d 00 61 00 69 00 6e 00 5c 00 [0-8] 53 00 74 00 61 00 72 00 74 00 20 00 50 00 61 00 67 00 65 00 [0-8] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 63 00 68 00 65 00 72 00 63 00 68 00 65 00 2e 00 75 00 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = "\\Windows\\CurrentVersion\\Run\\binternet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_SY_2147654409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.SY"
        threat_id = "2147654409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%w%w%w.08%184%19.%c%o%m" ascii //weight: 1
        $x_1_2 = "MyStartJSName" ascii //weight: 1
        $x_1_3 = "\\Adobe\\Adobe Utilities\\ExtendScript Toolkit CS4" ascii //weight: 1
        $x_1_4 = "goto   try" ascii //weight: 1
        $x_1_5 = "www.82019.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_TX_2147655263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.TX"
        threat_id = "2147655263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 04 8d 44 24 14 8a 96 ?? e1 40 00 80 f2 ?? 88 14 30 46 83 fe 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {73 04 8d 4c 24 4c 6a 01 53 53 51 68 ?? ba 40 00 53 ff d0 39 6c 24 28 72 0d 8b 44 24 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_QY_2147655265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.QY"
        threat_id = "2147655265"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 c4 14 33 c0 85 ff 76 08 30 04 30 40 3b c7 72 f8 80 24 37 00}  //weight: 10, accuracy: High
        $x_1_2 = {5c 00 6d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 5c 00 66 00 69 00 72 00 65 00 66 00 6f 00 78 00 5c 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 73 00 5c 00 25 00 73 00 5c 00 70 00 72 00 65 00 66 00 73 00 2e 00 6a 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 77 00 65 00 62 00 32 00 6e 00 65 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 00 65 00 41 00 72 00 65 00 57 00 65 00 41 00 72 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "user_pref(%cbrowser.startup.homepage" ascii //weight: 1
        $x_1_7 = "homepage_is_newtabpage" ascii //weight: 1
        $x_1_8 = "DisableNXShowUI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_TY_2147655459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.TY"
        threat_id = "2147655459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 75 69 63 6b 20 4c 61 75 6e 63 68 [0-3] 68 74 74 70 3a 2f 2f 77 77 77 2e 31 31 34 2e}  //weight: 1, accuracy: Low
        $x_1_2 = "test.114.com.cn" ascii //weight: 1
        $x_1_3 = "\\WinRAR\\i.ico" ascii //weight: 1
        $x_1_4 = {ce d2 b5 c4 b8 f6 d0 d4 b5 bc ba bd ca d7 d2 b3 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {68 04 01 00 00 50 6a ff 51 6a 00 6a 00 ff d6 8b 44 24 30 8d 8c 24 d0 01 00 00 6a 02 51 8b 10 50 ff 52 18 8b 44 24 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Startpage_TZ_2147655475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.TZ"
        threat_id = "2147655475"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[HKEY_CLASSES_ROOT\\mss4file\\shell\\open\\command]" wide //weight: 1
        $x_1_2 = "@=hex(2):22,00,43,00,3a,00,5c,00,70,00,72,00,6f,00,67,00,72,00,61,00,7e,00,31,\\" wide //weight: 1
        $x_1_3 = "  00,5c,00,49,00,6e,00,74,00,65,00,72,00,6e,00,7e,00,31,00,5c,00,69,00,65,00,\\" wide //weight: 1
        $x_1_4 = "  78,00,70,00,6c,00,6f,00,72,00,65,00,2e,00,65,00,78,00,65,00,22,00,20,00,22,\\" wide //weight: 1
        $x_1_5 = "  00,68,00,74,00,74,00,70,00,3a,00,2f,00,2f," wide //weight: 1
        $x_1_6 = {2f 65 76 65 72 79 3a 4d 6f 6e 64 61 79 2c 54 75 65 73 64 61 79 2c 57 65 64 6e 65 73 64 61 79 2c 54 68 75 72 73 64 61 79 2c 46 72 69 64 61 79 2c 53 61 74 75 72 64 61 79 2c 53 75 6e 64 61 79 20 20 63 6d 64 2e 65 78 65 20 20 2f 63 20 63 6f 70 79 20 22 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 77 69 6e 72 61 72 5c [0-16] 2e 6d 73 73 34 22 20 22 25 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 25 5c [0-16] 2e 6d 73 73 34 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_UD_2147655755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.UD"
        threat_id = "2147655755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {51 75 69 63 6b 20 4c 61 75 6e 63 68 00 00 20 68 74 74 70 3a 2f 2f 77 77 77 2e 31 31 34 2e 63 6f 6d 2e 63 6e 2f}  //weight: 5, accuracy: High
        $x_1_2 = "Mozilla Firefox.lnk" ascii //weight: 1
        $x_1_3 = "Internet Explorer.lnk" ascii //weight: 1
        $x_5_4 = {eb 7a 8b 44 24 (1c|2c) 51 50 8b 10 ff 52 50 8b 44 24 (1c|2c) 68 ?? ?? ?? 00 50 8b 08 ff 51 2c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_UG_2147656493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.UG"
        threat_id = "2147656493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\360seURL" ascii //weight: 1
        $x_1_2 = "\\dao.ico" ascii //weight: 1
        $x_1_3 = "Start Page" ascii //weight: 1
        $x_1_4 = "\\Internet Explorer.lnk" ascii //weight: 1
        $x_1_5 = "aHR0cDovL3d3dy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_XS_2147657184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.XS"
        threat_id = "2147657184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ":\\Documents and Settings\\STCTR\\Desktop\\src" wide //weight: 1
        $x_1_2 = "\\windowe.exe" wide //weight: 1
        $x_1_3 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\\\DisableRegistryTools" wide //weight: 1
        $x_1_4 = "\\CurrentVersion\\Run\\Winlogon" wide //weight: 1
        $x_1_5 = "user_pref(\"browser.startup.homepage\", \"" wide //weight: 1
        $x_1_6 = {5c 00 70 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 5c 00 5c 00 65 00 6e 00 61 00 62 00 6c 00 65 00 6c 00 75 00 61 00 [0-8] 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 [0-8] 52 00 45 00 47 00 5f 00 44 00 57 00 4f 00 52 00 44 00 [0-8] 72 00 65 00 67 00 77 00 72 00 69 00 74 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_UI_2147657488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.UI"
        threat_id = "2147657488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 74 20 45 78 89 11 83 c3 04 03 cb 6b db 00 ba 70 6c 6f 72 89 11 83 c3 04 03 cb 6b db 00 ba 65 72 5c 5c 89 11 83 c3 04 03 cb 6b db 00 ba 4d 61 69 6e}  //weight: 1, accuracy: High
        $x_1_2 = {65 8b e5 5d c3 1b 00 c6 05 ?? ?? ?? ?? 68 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 2f c6 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_UT_2147660154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.UT"
        threat_id = "2147660154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {40 c1 e0 02 2b e0 8d 3c 24 51 c7 45 fc 01 00 00 00 8d 75 08 8b 1e 83 c6 04 51 e8}  //weight: 5, accuracy: High
        $x_1_2 = "http://jmp.net.cn/?" ascii //weight: 1
        $x_1_3 = "Start Page" ascii //weight: 1
        $x_1_4 = {2e 6c 6e 6b [0-4] 68 61 6f 31 32 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_VD_2147670473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.VD"
        threat_id = "2147670473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {7b 5b 28 31 ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 3d 68 74 74 70 3a 2f 2f 77 77 77 2e ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 63 6f 6d 2f 29 5d 7d}  //weight: 10, accuracy: Low
        $x_10_2 = {7b 5b 28 31 ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 3d 43 4c 53 49 44 5c 7b 38 37 31 43 35 33 38 30 2d 34 32 41 30 2d 31 30 36 39 2d 41 32 45 41 2d 30 38 30 30 32 42 33 30 33 30 39 44 7d 5c 73 68 65 6c 6c 5c 4f 70 65 6e 48 6f 6d 65 50 61 67 65 5c 43 6f 6d 6d 61 6e 64 29 5d 7d}  //weight: 10, accuracy: Low
        $x_1_3 = {7b 5b 28 31 ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 3d 53 6f 66 74 77 61 72 65 5c 4e 65 74 43 75 62 65 32 30 31 32 29 5d 7d}  //weight: 1, accuracy: Low
        $x_1_4 = {7b 5b 28 31 ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 3d 53 6f 66 74 77 61 72 65 5c 55 6e 69 4e 6f 64 65 32 36 31 30 29 5d 7d}  //weight: 1, accuracy: Low
        $x_1_5 = {7b 5b 28 31 ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 3d 53 6f 66 74 77 61 72 65 5c 33 36 30 5c 33 36 30 73 65 33 29 5d 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_VH_2147679623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.VH"
        threat_id = "2147679623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "||Vsrrbsrrasss" ascii //weight: 1
        $x_1_2 = "\\Users\\User\\Desktop\\hta\\Project1.vbp" wide //weight: 1
        $x_1_3 = "taskkill.exe /f /t /im firefox.exe" wide //weight: 1
        $x_1_4 = "user_pref(\"browser.startup.page\"," wide //weight: 1
        $x_1_5 = "urls_to_restore_on_startup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Startpage_VM_2147680387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.VM"
        threat_id = "2147680387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6a 01 51 3c 05 b9 ?? ?? ?? ?? 8b c4 77 ?? 89 a5 ?? ?? ff ff 50 e8 ?? ?? ?? ?? 51 8b cc c7 45 ?? 00 00 00 00 89 a5 ?? ?? ff ff 51 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 51 c6 45 ?? 01 8b d4 89 a5 ?? ?? ff ff 52 8d 8d ?? ?? ff ff e8 ?? ?? ?? ?? c7 45 ?? ff ff ff ff e8 ?? ?? ?? ?? 83 c4 10 eb ?? 89 a5 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 51 8b cc c7 45 ?? 02 00 00 00 89 a5 ?? ?? ff ff 51 b9 ?? ?? ?? ?? e8}  //weight: 3, accuracy: Low
        $x_1_2 = "Home Page plugin updater" wide //weight: 1
        $x_1_3 = "\\Home Page\\Updater" wide //weight: 1
        $x_1_4 = "D:\\Plugins for Browsers\\HomePages\\installers\\_HomePage\\HomePageInstaller\\Release\\HomePageInstaller.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Startpage_XW_2147697309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.XW"
        threat_id = "2147697309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf 89 77 3c c7 47 40 01 00 00 00 c7 47 50 fb 5d 77 08 e8}  //weight: 1, accuracy: High
        $x_1_2 = "gamegogle|123rede|jogostempo" wide //weight: 1
        $x_1_3 = "top8844|321oyun|aqovd|qqovd" wide //weight: 1
        $x_1_4 = {00 00 26 00 74 00 6d 00 3d 00 00 00 00 00 26 00 75 00 69 00 64 00 3d 00 00 00 3f 00 6f 00 65 00 6d 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {25 00 73 00 2f 00 74 00 70 00 6c 00 2f 00 25 00 73 00 2f 00 66 00 61 00 76 00 69 00 63 00 6f 00 6e 00 2e 00 69 00 63 00 6f 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 52 00 65 00 73 00 74 00 6f 00 72 00 65 00 4f 00 6e 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 55 00 52 00 4c 00 73 00 00 00 00 00 31 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 4d 00 61 00 69 00 6e 00 [0-6] 53 00 74 00 61 00 72 00 74 00 20 00 50 00 61 00 67 00 65 00 [0-4] 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5f 00 50 00 61 00 67 00 65 00 5f 00 55 00 52 00 4c 00}  //weight: 1, accuracy: Low
        $x_1_8 = "\\jiangt\\VC\\Bind\\trunk\\output\\bin\\BData" ascii //weight: 1
        $x_1_9 = {47 00 6f 00 6f 00 67 00 6c 00 65 00 20 00 [0-10] 6d 00 65 00 2e 00 65 00 78 00 65 00 00 00 00 00 63 00 68 00 72 00 6f 00 00 00}  //weight: 1, accuracy: Low
        $x_1_10 = {53 00 74 00 61 00 72 00 74 00 75 00 70 00 55 00 52 00 4c 00 73 00 00 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 52 00 65 00 73 00 74 00 6f 00 72 00 65 00 4f 00 6e 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 00 2f 00 73 00 76 00 33 00 2f 00 4c 00 6f 00 67 00 2f 00 6c 00 6f 00 67 00 45 00 78 00 65 00 63 00 2e 00 70 00 68 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {5c 00 55 00 73 00 65 00 72 00 20 00 50 00 69 00 6e 00 6e 00 65 00 64 00 5c 00 54 00 61 00 73 00 6b 00 42 00 61 00 72 00 00 00 00 00 2e 00 6c 00 6e 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_13 = {25 00 49 00 36 00 34 00 75 00 00 00 73 00 76 00 31 00 00 00 77 00 77 00 77 00 2e 00 61 00 71 00 6f 00 76 00 64 00 2e 00 63 00 6f 00 6d 00 00 00 2e 00 63 00 6f 00 6d 00 00 00 00 00 77 00 77 00 77 00 2e 00}  //weight: 1, accuracy: High
        $x_1_14 = "oem=sv1&uid=" wide //weight: 1
        $x_1_15 = "_LOGICAL VOLUME&tm=" wide //weight: 1
        $x_1_16 = {73 00 74 00 65 00 6d 00 70 00 6f 00 7c 00 74 00 6f 00 70 00 38 00 00 00 72 00 65 00 64 00 65 00 7c 00 6a 00 6f 00 67 00 6f 00}  //weight: 1, accuracy: High
        $x_1_17 = {79 00 75 00 6e 00 7c 00 61 00 71 00 00 00 00 00 38 00 34 00 34 00 7c 00 33 00 32 00 31 00 6f 00}  //weight: 1, accuracy: High
        $x_1_18 = {5c 00 73 00 76 00 33 00 5c 00 4c 00 6f 00 67 00 5c 00 6c 00 6f 00 67 00 45 00 78 00 65 00 63 00 2e 00 70 00 68 00 70 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Startpage_AGL_2147705841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.AGL"
        threat_id = "2147705841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "user_pref(\"browser.startup.homepage\", \"http://www.okgen.com/?ref=ms\");" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 61 6c 77 61 72 65 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 5c 72 65 70 61 69 72 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_PVO_2147710746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage.PVO!bit"
        threat_id = "2147710746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 5c 53 74 61 72 74 20 50 61 67 65 [0-16] 77 77 77 2e 32 33 34 35 2e 63 6f 6d 2f 3f 6b 37 34 34 36 30 36 36 34 30}  //weight: 1, accuracy: Low
        $x_1_2 = "VMProtect begin" ascii //weight: 1
        $x_1_3 = {00 57 54 57 69 6e 64 6f 77 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Startpage_2147731966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Startpage"
        threat_id = "2147731966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MailHook.MailTo.1" ascii //weight: 10
        $x_10_2 = {48 6f 6d 65 20 49 6d 70 72 6f 76 65 6d 65 6e 74 00 00 00 00 48 6f 6d 65 20 49 6e 73 75 72 61 6e 63 65}  //weight: 10, accuracy: High
        $x_10_3 = {45 64 75 63 61 74 69 6f 6e 00 00 57 6f 6d 65 6e 00 00 00 57 69 6e 65}  //weight: 10, accuracy: High
        $x_10_4 = "searchforge.com" ascii //weight: 10
        $x_5_5 = "%SYSTEMROOT%\\System32\\drivers\\etc\\hosts" ascii //weight: 5
        $x_1_6 = "www.008k.com" ascii //weight: 1
        $x_1_7 = "livesexlist.com" ascii //weight: 1
        $x_1_8 = "htt'+'p://adu'+'lt.sea'+'rchfo'" ascii //weight: 1
        $x_1_9 = "http://auto.ie.searchforge.com/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

