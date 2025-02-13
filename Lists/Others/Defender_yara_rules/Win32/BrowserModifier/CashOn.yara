rule BrowserModifier_Win32_CashOn_17747_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CashOn"
        threat_id = "17747"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CashOn"
        severity = "15"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cashon.co.kr" ascii //weight: 1
        $x_1_2 = "auction.co.kr" ascii //weight: 1
        $x_1_3 = "dnshop.co.kr" ascii //weight: 1
        $x_1_4 = "cjmall.co.kr" ascii //weight: 1
        $x_1_5 = "gmarket.co.kr" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_8 = "GetWindowsDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_CashOn_17747_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CashOn"
        threat_id = "17747"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CashOn"
        severity = "15"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "previous_update_exe" ascii //weight: 2
        $x_4_2 = {43 61 73 68 4f 6e 5c 62 69 6e 00 00 2a 2e 65 78 65 00 00 00 55 50 44 41 54 45 52 00 45 6e 61 62 6c 65 20 42 72 6f 77 73 65 72 20 45 78 74 65 6e 73 69 6f 6e 73}  //weight: 4, accuracy: High
        $x_2_3 = "ncserv*.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_CashOn_17747_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CashOn"
        threat_id = "17747"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CashOn"
        severity = "15"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TCashOn" ascii //weight: 1
        $x_2_2 = "C:\\Program Files\\CashOn\\data\\popup.dat" ascii //weight: 2
        $x_3_3 = "#cashon_rt" ascii //weight: 3
        $x_2_4 = "SOFTWARE\\CashOn\\" ascii //weight: 2
        $x_3_5 = "http://www.cashon.co.kr/search/search.php" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_CashOn_17747_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CashOn"
        threat_id = "17747"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CashOn"
        severity = "15"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "D:\\Project\\Press\\premiere.or.kr\\Source\\PSCInfo.dll_20" ascii //weight: 4
        $x_3_2 = "http://smart.linkprice.com/sem/overture_sponsor_search.php?maxcnt=&js=2&type=" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_CashOn_17747_4
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CashOn"
        threat_id = "17747"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CashOn"
        severity = "15"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cashonupdate" ascii //weight: 1
        $x_2_2 = "http://www.cashon.co.kr/app/app.php?url=" ascii //weight: 2
        $x_2_3 = "SOFTWARE\\CashOn\\" ascii //weight: 2
        $x_2_4 = "script.shop-guide.co.kr" ascii //weight: 2
        $x_2_5 = "Dispatch interface for cashbho ObjectW" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_CashOn_17747_5
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CashOn"
        threat_id = "17747"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CashOn"
        severity = "15"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SOFTWARE\\CashOn\\" ascii //weight: 2
        $x_1_2 = "bho_Date" ascii //weight: 1
        $x_1_3 = "Updateexe_Date" ascii //weight: 1
        $x_2_4 = "{01E04581-4EEE-11D0-BFE9-00AA005B4383}" ascii //weight: 2
        $x_2_5 = "http://www.cashon.co.kr/app/install.php?" ascii //weight: 2
        $x_2_6 = "C:\\Program Files\\Cashon\\bin\\" ascii //weight: 2
        $x_2_7 = "CashonMediaHoon" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_CashOn_17747_6
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/CashOn"
        threat_id = "17747"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "CashOn"
        severity = "15"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Windows Driver for Cashontool" ascii //weight: 2
        $x_2_2 = "cashonbho" ascii //weight: 2
        $x_2_3 = "SOFTWARE\\CashOn\\" ascii //weight: 2
        $x_2_4 = "CashOn\\bin\\N" ascii //weight: 2
        $x_1_5 = "{CE2744FF-57FE-42AC-9F0D-7C38C00E00E8}" ascii //weight: 1
        $x_1_6 = "{A13E6D04-17B3-40FC-B69A-C47914BA377E}" ascii //weight: 1
        $x_2_7 = "Cashon NcService" ascii //weight: 2
        $x_4_8 = "http://www.cashon.co.kr/app/uninstall.php?" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

