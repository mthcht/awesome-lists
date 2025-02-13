rule BrowserModifier_Win32_Prifou_224074_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Prifou"
        threat_id = "224074"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Prifou"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PrcFountain" ascii //weight: 1
        $x_1_2 = "Price Fountain" ascii //weight: 1
        $x_1_3 = {66 78 61 63 78 71 36 38 0d 6f 71 71 00}  //weight: 1, accuracy: High
        $x_1_4 = {59 61 78 72 70 78 57 6a 71 78 46 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Prifou_224074_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Prifou"
        threat_id = "224074"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Prifou"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "EInvalidOperation" ascii //weight: 1
        $x_1_2 = "virtualalloc" ascii //weight: 1
        $x_1_3 = "VirtualFree" ascii //weight: 1
        $x_1_4 = {8b 45 fc 80 b8 ?? 00 00 00 00 74 ec}  //weight: 1, accuracy: Low
        $x_1_5 = {ff ff 84 c0 74 ?? e8 ?? ?? 00 00 68}  //weight: 1, accuracy: Low
        $x_1_6 = {ff ff 5d c2 10 00 0a 00 a1 ?? ?? ?? 00 8b 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule BrowserModifier_Win32_Prifou_224074_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Prifou"
        threat_id = "224074"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Prifou"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 01 00 00 00 8b 06 0f b6 44 18 ff 89 45 f4 8b c6 e8 ?? ?? ?? ?? 8b 55 f8 8b 4d f4 8a 14 0a 88 54 18 ff 43 4f 75 de 33 c0 5a 59 59}  //weight: 1, accuracy: Low
        $x_1_2 = "\\UpdateProc\\UpdateTask.exe" wide //weight: 1
        $x_1_3 = "\\UpdateProc\\config.dat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Prifou_224074_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Prifou"
        threat_id = "224074"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Prifou"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\PriceMeter" wide //weight: 1
        $x_1_2 = "pricemeterw.exe" wide //weight: 1
        $x_1_3 = "__pmLog_.txt" wide //weight: 1
        $x_1_4 = "cef_binary_dealply" ascii //weight: 1
        $x_1_5 = "ChickenApp.openURL = function(url)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Prifou_224074_4
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Prifou"
        threat_id = "224074"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Prifou"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Price Fountain" wide //weight: 1
        $x_1_2 = "kipi2.storepm.com/index6.php" wide //weight: 1
        $x_1_3 = "type=offb&topic=urldat&data=1" wide //weight: 1
        $x_1_4 = "SuzanDLL\\Release\\suzanw.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Prifou_224074_5
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Prifou"
        threat_id = "224074"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Prifou"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\CScript.exe\"  //b //e:vbscript //nologo" ascii //weight: 1
        $x_1_2 = "http://ins.pricejs.net/dealdo/install-report?type=install" ascii //weight: 1
        $x_1_3 = "&instgrp=" ascii //weight: 1
        $x_1_4 = "dll-file-name" ascii //weight: 1
        $x_1_5 = "\\Rkey.dat" ascii //weight: 1
        $x_1_6 = "\\Start Menu\\Programs\\Booking .lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule BrowserModifier_Win32_Prifou_224074_6
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Prifou"
        threat_id = "224074"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Prifou"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\PriceMeter" wide //weight: 1
        $x_1_2 = "SOFTWARE\\BrowserOptout" wide //weight: 1
        $x_1_3 = "pricemeterw.exe" wide //weight: 1
        $x_1_4 = "type=offinst&topic=downstart" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Prifou_224074_7
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Prifou"
        threat_id = "224074"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Prifou"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PriceFountain\\pricefountain.exe" wide //weight: 1
        $x_1_2 = "PriceFountain_DLL" wide //weight: 1
        $x_1_3 = "Debbie_" wide //weight: 1
        $x_1_4 = {3c 73 63 72 69 70 74 20 73 72 63 3d 27 68 74 74 70 3a 2f 2f 6a 2e 70 72 69 63 65 6a 73 2e 6e 65 74 2f [0-7] 2f 63 6f 6d 6d 6f 6e 2e 6a 73 3f 63 68 61 6e 6e 65 6c 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Prifou_224074_8
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Prifou"
        threat_id = "224074"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Prifou"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\PriceFountain" wide //weight: 1
        $x_1_2 = "(ePriceFountainScriptObj)" wide //weight: 1
        $x_1_3 = "CLSID\\{b608cc98-54de-4775-96c9-097de398500c}" wide //weight: 1
        $x_1_4 = "instgrp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Prifou_224074_9
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Prifou"
        threat_id = "224074"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Prifou"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\PriceMeter" wide //weight: 1
        $x_1_2 = "pricemeterw.exe" wide //weight: 1
        $x_1_3 = "type=offinst&topic=wdrun" wide //weight: 1
        $x_1_4 = "type=offinst&topic=pm2kry2" wide //weight: 1
        $x_1_5 = "WatchDog\\Release\\pricemeterw.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule BrowserModifier_Win32_Prifou_224074_10
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Prifou"
        threat_id = "224074"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Prifou"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\PriceMeterExpress" wide //weight: 1
        $x_1_2 = "http://www.pricemeter.net/" wide //weight: 1
        $x_1_3 = "http://trail.filespm.com/dealdo/install-report" wide //weight: 1
        $x_1_4 = "DealPly\\DealPlySetup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Prifou_224074_11
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Prifou"
        threat_id = "224074"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Prifou"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\CScript.exe\"  //b //e:vbscript //nologo" ascii //weight: 1
        $x_1_2 = "\\Uninstall\\PriceFountain" ascii //weight: 1
        $x_1_3 = {44 69 73 70 6c 61 79 4e 61 6d 65 00 50 72 69 63 65 46 6f 75 6e 74 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = "PF Installer" ascii //weight: 1
        $x_1_5 = "http://ins.pricejs.net/dealdo/install-report?type=install" ascii //weight: 1
        $x_1_6 = {2f 69 6e 73 74 61 6c 6c 20 2f 55 6e 4e 6d 3d 22 55 70 64 61 74 65 05 00 66 6f 72 05 00 50 72 69 63 65 46 6f 75 6e 74 61 69 6e 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule BrowserModifier_Win32_Prifou_224074_12
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Prifou"
        threat_id = "224074"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Prifou"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xpi\\content\\pricemeterexpress.xul" wide //weight: 1
        $x_1_2 = "files\\PriceMeterExpress.crx" wide //weight: 1
        $x_1_3 = "files\\PriceMeterExpress.xpi" wide //weight: 1
        $x_1_4 = "files\\PriceMeterExpressIE.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Prifou_224074_13
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Prifou"
        threat_id = "224074"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Prifou"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\PriceMeter" wide //weight: 1
        $x_1_2 = "Software\\DealPlyLive" wide //weight: 1
        $x_1_3 = "$browser-identifier-ie" wide //weight: 1
        $x_1_4 = "http://www.pricemeter.net/go/postinstall/?action=install&partner=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Prifou_224074_14
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Prifou"
        threat_id = "224074"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Prifou"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\PriceFountain" wide //weight: 1
        $x_1_2 = "suzan_wdrun" wide //weight: 1
        $x_1_3 = "suzan_wddowo" wide //weight: 1
        $x_1_4 = "suzan_wdnotrun" wide //weight: 1
        $x_1_5 = "\\logs\\wd.log" wide //weight: 1
        $x_1_6 = "https://dumpster-server.herokuapp.com/manager/query" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Prifou_224074_15
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Prifou"
        threat_id = "224074"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Prifou"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {72 65 6c 65 61 73 65 2e 64 6c 6c 00 52 75 6e 00}  //weight: 20, accuracy: High
        $x_20_2 = {58 59 5a 50 68 52 75 6e 00 54 52 51 e8 04 00 00 00 ff d0 83 c4 04 c3}  //weight: 20, accuracy: High
        $x_1_3 = "\\RunOnce\\BRAND_NAME\",\"WSCRIPT_CMD_NAME /E:vbscript /B \"\"\" & WScript.ScriptFullName" wide //weight: 1
        $x_1_4 = "\\UpdateProc\\UpdateTask.exe" wide //weight: 1
        $x_1_5 = "\\UpdateProc\\bkup.dat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Prifou_224074_16
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Prifou"
        threat_id = "224074"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Prifou"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PMExpressCls.injectScriptFromUrl(url);" wide //weight: 1
        $x_1_2 = "DealPlyConfigLocalCls.prototype.getPartner" wide //weight: 1
        $x_1_3 = "&appTitle=PriceMeter+Express" wide //weight: 1
        $x_1_4 = "http://www.pricemeter.net/" wide //weight: 1
        $x_1_5 = "SOFTWARE\\PriceMeter" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Prifou_224074_17
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Prifou"
        threat_id = "224074"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Prifou"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "92"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "SOFTWARE\\PriceFountain" wide //weight: 30
        $x_30_2 = "pricejs.net" wide //weight: 30
        $x_30_3 = "https://dumpster-server.herokuapp.com/manager/query" wide //weight: 30
        $x_1_4 = "suzan_url_inj" wide //weight: 1
        $x_1_5 = "suzan_beforedllinj" wide //weight: 1
        $x_1_6 = "suzan_already_injected" wide //weight: 1
        $x_1_7 = "suzandll_file_path" wide //weight: 1
        $x_1_8 = "suzandll_file_name" wide //weight: 1
        $x_1_9 = "SuzanEXE.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_30_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Prifou_224074_18
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Prifou"
        threat_id = "224074"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Prifou"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\PriceFountain" wide //weight: 1
        $x_1_2 = "PriceFountainIE.dll" wide //weight: 1
        $x_1_3 = "pricefountain.exe" wide //weight: 1
        $x_1_4 = "$browser-identifier-ie" wide //weight: 1
        $x_1_5 = "http://ins.pricejs.net/dealdo/install-report" wide //weight: 1
        $x_1_6 = "http://www.PriceFountain.net/go/postinstall/?action=install&partner=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

