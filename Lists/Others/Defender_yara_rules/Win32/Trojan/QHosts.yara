rule Trojan_Win32_QHosts_B_2147597883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QHosts.B"
        threat_id = "2147597883"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QHosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "escrow.com" wide //weight: 10
        $x_10_2 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_3 = "199.238.130.101" wide //weight: 10
        $x_10_4 = "\\system32\\drivers\\etc\\hosts" wide //weight: 10
        $x_10_5 = ":\\vir\\vrz\\vrz\\screencapture\\screenCpature.vbp" wide //weight: 10
        $x_10_6 = "Please see the picture below where eBay sugest to use only escrow.com" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QHosts_C_2147597884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QHosts.C"
        threat_id = "2147597884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QHosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "54"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "> nul" ascii //weight: 10
        $x_10_2 = "/c  del" ascii //weight: 10
        $x_10_3 = "\\drivers\\etc\\hosts" ascii //weight: 10
        $x_10_4 = "GetSystemDirectoryA" ascii //weight: 10
        $x_10_5 = "Copyright (c) 1993-1999 Microsoft Corp." ascii //weight: 10
        $x_1_6 = "27.0.0.3" ascii //weight: 1
        $x_1_7 = "61.129.115.90" ascii //weight: 1
        $x_1_8 = "qqq.61139.com" ascii //weight: 1
        $x_1_9 = "www.jb315.cn" ascii //weight: 1
        $x_1_10 = "wow.61139.com" ascii //weight: 1
        $x_1_11 = "ww.baidu3.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_QHosts_J_2147629718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QHosts.J"
        threat_id = "2147629718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QHosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "34.195.153.94 apis.google.com" ascii //weight: 1
        $x_1_2 = "34.195.153.94 www.googleadservices.com" ascii //weight: 1
        $x_1_3 = {bb 1d 00 00 73 ?? 8b ?? ?? [0-3] 0f be ?? ?? ?? [0-3] 83 ?? ?? 8b ?? ?? [0-3] 88 ?? ?? ?? [0-3] eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_QHosts_N_2147634634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QHosts.N"
        threat_id = "2147634634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QHosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 65 63 68 6f 20 6f 66 66 0d 0a 40 65 63 68 6f 20 [0-4] 2e [0-4] 2e [0-4] 2e [0-5] 77 77 77 2e 62 61 6e 6b 6f 66 61 6d 65 72 69 63 61 2e 63 6f 6d 20 20 3e 3e 25 77 69 6e 64 69 72 25 5c 53 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QHosts_S_2147641624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QHosts.S"
        threat_id = "2147641624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QHosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\system32\\drivers\\etc\\hosts" wide //weight: 2
        $x_3_2 = "C:\\inon\\Project1.vbp" wide //weight: 3
        $x_2_3 = "www.bancomer.com" wide //weight: 2
        $x_2_4 = "www.bbva.com.mx" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QHosts_U_2147646251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QHosts.U"
        threat_id = "2147646251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QHosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2f 63 6d 2e 70 68 70 3f 69 64 3d [0-4] 26 68 61 73 68 3d}  //weight: 2, accuracy: Low
        $x_2_2 = {31 32 37 2e 30 2e 30 2e 31 [0-16] 6c 6f 63 61 6c 68 6f 73 74}  //weight: 2, accuracy: Low
        $x_2_3 = "drivers\\etc\\hosts" ascii //weight: 2
        $x_1_4 = "corporatefactories.com" ascii //weight: 1
        $x_1_5 = "VirusBlokAda" ascii //weight: 1
        $x_1_6 = "ms.kaspersky.com" ascii //weight: 1
        $x_1_7 = "skypedeals.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_QHosts_Y_2147648137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QHosts.Y"
        threat_id = "2147648137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QHosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "54"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "del %windir%\\system32\\drivers\\etc\\hosts" ascii //weight: 50
        $x_2_2 = "echo 200.63.43.24" ascii //weight: 2
        $x_1_3 = "echo 66.23.239.228" ascii //weight: 1
        $x_1_4 = "echo 208.84.148.239" ascii //weight: 1
        $x_1_5 = "bbva.cl >>" ascii //weight: 1
        $x_1_6 = "scotiabank.com >>" ascii //weight: 1
        $x_1_7 = "viabcp.com >>" ascii //weight: 1
        $x_1_8 = "officebanking.cl >>" ascii //weight: 1
        $x_1_9 = "bancofalabella.cl >>" ascii //weight: 1
        $x_1_10 = "bancoestado.cl >>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 4 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_QHosts_AD_2147650179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QHosts.AD"
        threat_id = "2147650179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QHosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo 184.82.118.47  http://santander.cl >> %windir%\\system32\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_2 = "start http://www.gusanito.com/" ascii //weight: 1
        $x_1_3 = "exitpostal_gusanito.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QHosts_AE_2147650591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QHosts.AE"
        threat_id = "2147650591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QHosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=91.217.153.19" ascii //weight: 1
        $x_1_2 = "@echo off" ascii //weight: 1
        $x_1_3 = "attrib -h -r" ascii //weight: 1
        $x_1_4 = "=\\system32\\drivers\\etc\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QHosts_AG_2147651624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QHosts.AG"
        threat_id = "2147651624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QHosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {84 c0 74 4e b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 50 e8 ?? ?? ?? ff 68 e8 03 00 00 e8 ?? ?? ?? ff b8 ?? ?? ?? 00}  //weight: 10, accuracy: Low
        $x_10_2 = {6d 61 67 65 6e 74 73 65 74 75 70 2e 65 78 65 [0-7] 55 8b ec 33 c0 55 68 ?? ?? ?? 00 64 ff 30 64 89 20 33 c0 5a 59 59 64 89 10 68 ?? ?? ?? 00}  //weight: 10, accuracy: Low
        $x_10_3 = {6d 61 67 65 6e 74 2e 65 78 65 [0-7] 55 8b ec 33 c0 55 68 ?? ?? ?? 00 64 ff 30 64 89 20 33 c0 5a 59 59 64 89 10 68 ?? ?? ?? 00}  //weight: 10, accuracy: Low
        $x_10_4 = "exe.agent.mail.ru" ascii //weight: 10
        $x_10_5 = ":\\Program Files\\Mail.Ru\\Agent\\magent.exe" ascii //weight: 10
        $x_10_6 = {77 69 6e 61 6d 70 2e 65 78 65 00 [0-16] 00 6d 61 67 65 6e 74 2e 65 78 65 00}  //weight: 10, accuracy: Low
        $x_5_7 = {6f 6f 2e 63 6f 6d 00 90 02 10 00 67 6c 65 2e 63 6f 6d}  //weight: 5, accuracy: High
        $x_5_8 = ":/WINDOWS/system32/drivers/etc/hosts" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_QHosts_AH_2147652692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QHosts.AH"
        threat_id = "2147652692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QHosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {4b 83 fb 00 76 06 40 80 30 ?? eb f4 5b}  //weight: 4, accuracy: Low
        $x_2_2 = "\\system32\\drivers\\etc\\hosts" wide //weight: 2
        $x_1_3 = "bancodechile.cl" ascii //weight: 1
        $x_1_4 = "bancoestado.cl" ascii //weight: 1
        $x_1_5 = "bbva.cl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_QHosts_AK_2147653831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QHosts.AK"
        threat_id = "2147653831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QHosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\e#t#c\\h#o#s#ts" ascii //weight: 1
        $x_1_2 = "\"Di#s#ab#le#" ascii //weight: 1
        $x_1_3 = "\\hst.pn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QHosts_AL_2147653837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QHosts.AL"
        threat_id = "2147653837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QHosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "rename C:\\WINDOWS\\system32\\drivers\\etc\\hosts service" ascii //weight: 1
        $x_1_2 = {65 63 68 6f 20 03 00 2e 03 00 2e 03 00 2e 03 00 20 62 61 6e 63 6f 65 73 74 61 64 6f 2e 63 6c 20 3e 3e 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QHosts_AN_2147654337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QHosts.AN"
        threat_id = "2147654337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QHosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".CreateShortcut(\"c:\\AdobeUpdate.lnk\")" ascii //weight: 1
        $x_1_2 = "\\etc\\hosts\"\" /Y && attrib +H" ascii //weight: 1
        $x_1_3 = "/js/data/js.dll" ascii //weight: 1
        $x_1_4 = "\\Keyboard Layout\" /v \"Scancode Map\"" ascii //weight: 1
        $x_1_5 = "NET STOP wscsvc && NET STOP sharedaccess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QHosts_AP_2147656265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QHosts.AP"
        threat_id = "2147656265"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QHosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 30 34 5c [0-16] 2e 74 78 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {25 30 34 5c [0-16] 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {25 30 34 5c [0-16] 2e 6a 70 67 00}  //weight: 1, accuracy: Low
        $x_1_4 = "%02\\System32\\drivers\\etc\\" ascii //weight: 1
        $x_1_5 = {65 63 68 6f 20 25 [0-16] 25 20 3e 3e 20 20 68 6f 73 74 73 0d 0a}  //weight: 1, accuracy: Low
        $x_1_6 = {65 63 68 6f 20 20 25 [0-16] 25 20 20 20 3e 3e 20 20 68 6f 73 74 73 0d 0a}  //weight: 1, accuracy: Low
        $x_1_7 = {0d 0a 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 0d 0a}  //weight: 1, accuracy: High
        $x_1_8 = "=%systemroot%%" ascii //weight: 1
        $x_1_9 = {3d 6f 6e 74 61 6b 74 65 2e 0d 0a}  //weight: 1, accuracy: High
        $x_2_10 = {3d 2e 0d 0a 73 65 74 20 [0-16] 3d 72 0d 0a 73 65 74 20 [0-16] 3d 75 0d 0a}  //weight: 2, accuracy: Low
        $x_1_11 = {3a 2f 2f 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2e 72 75 00}  //weight: 1, accuracy: High
        $x_1_12 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 6f 6c 6f 6c 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_QHosts_BC_2147671235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QHosts.BC"
        threat_id = "2147671235"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QHosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 30 34 5c [0-16] 2e 76 62 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 4f 4b 49 20 3d 22 68 6f [0-4] 73 [0-4] 74 [0-4] 73}  //weight: 1, accuracy: Low
        $x_1_3 = "echo %shsha%%KOIL%%hule_kak%" ascii //weight: 1
        $x_1_4 = "%k.ru" ascii //weight: 1
        $x_1_5 = {64 72 69 76 65 72 73 22 2b [0-4] 2b 22 65 74 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QHosts_BF_2147678519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QHosts.BF"
        threat_id = "2147678519"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QHosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {2e 2e 5c 73 69 6d 2e 65 78 65 00}  //weight: 15, accuracy: High
        $x_1_2 = {5c 69 67 72 61 65 74 5f 69 5f 70 6f 65 74 2e 76 62 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 6d 61 73 73 69 72 75 65 74 5f 7a 69 76 65 74 69 2e 76 62 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 76 6c 61 73 74 65 2e 6c 69 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 73 6c 61 76 6e 69 5f 6d 61 6c 69 69 5f 72 69 63 68 61 72 64 5f 6e 65 6c 73 6f 6e 69 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 70 6f 6c 6f 76 69 6e 6b 61 6f 73 74 61 6e 6b 69 6e 73 6b 6f 69 2e 76 62 73 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 62 61 73 68 6e 69 5f 6b 69 61 61 2e 76 62 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_QHosts_BH_2147678730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QHosts.BH"
        threat_id = "2147678730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QHosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "GET /stat/tuk/ HTTP/1.1" ascii //weight: 5
        $x_5_2 = {2f 73 74 61 74 2f 74 75 6b 2f 00 06 00 3a 20 00 68 74 74 70 3a 2f 2f}  //weight: 5, accuracy: Low
        $x_2_3 = {66 c7 85 37 ff ff ff 01 68 8d 85 37 ff ff ff ba ?? ?? ?? ?? b1 c8 e8 ?? ?? ?? ?? 66 c7 05 ?? ?? ?? 00 01 73 66 c7 05 ?? ?? ?? 00 01 74}  //weight: 2, accuracy: Low
        $x_2_4 = {66 c7 85 09 fd ff ff 01 69 66 c7 85 d2 fd ff ff 01 5c 8d 95 d2 fd ff ff}  //weight: 2, accuracy: High
        $x_2_5 = {66 c7 85 d5 fc ff ff 01 68 66 c7 85 09 fd ff ff 01 69 66 c7 85 d2 fd ff ff 01 5c}  //weight: 2, accuracy: High
        $x_1_6 = {68 ee 73 74 73 20 20 00}  //weight: 1, accuracy: High
        $x_1_7 = {68 d0 be 73 74 73 00}  //weight: 1, accuracy: High
        $x_1_8 = {64 00 61 00 74 00 61 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = "XGRyaXZlcnNcZXRjXGhvc3Rz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_QHosts_BR_2147707736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QHosts.BR"
        threat_id = "2147707736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QHosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "127.0.0.1       www.ijinshan.com" ascii //weight: 5
        $x_5_2 = "127.0.0.1       kaba365.com" ascii //weight: 5
        $x_1_3 = "cmd /c taskkill /f /im QQExtrenal.exe" wide //weight: 1
        $x_1_4 = "C:\\WINDOWS\\system32\\drivers\\etc\\hosts" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

