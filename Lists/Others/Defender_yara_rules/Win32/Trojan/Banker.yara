rule Trojan_Win32_Banker_BD_2147633322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker.BD"
        threat_id = "2147633322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Borland\\Delphi\\Locales" wide //weight: 1
        $x_1_2 = "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"" wide //weight: 1
        $x_1_3 = "email=vaivamoslah@gmail.com" wide //weight: 1
        $x_1_4 = "from=inn@oi.com" wide //weight: 1
        $x_1_5 = "/envia.php" wide //weight: 1
        $x_1_6 = "Token inv" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banker_BF_2147648926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker.BF"
        threat_id = "2147648926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Telegrama_Online.bat" ascii //weight: 1
        $x_1_2 = {0d 0a 73 65 74 20 2d ?? ?? ?? ?? 2d 3d ?? 0d 0a 73 65 74 20 2d ?? ?? ?? ?? 2d 3d ?? 0d 0a 25 2d ?? ?? ?? ?? 2d 25 25 2d ?? ?? ?? ?? 2d 25 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banker_K_2147655887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker.K"
        threat_id = "2147655887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "function FindProxyForURL(url, host)" ascii //weight: 1
        $x_1_2 = "for /f \"tokens=*\" %%z in ('dir \"%homepath%\\..\" /b /s" ascii //weight: 1
        $x_1_3 = "dnsResolve(\"google.portalvipbrasil.com\");" ascii //weight: 1
        $x_1_4 = "reg.exe add \"%key%\" /v \"AutoConfigUrl\" /d \"file://%_aaa%\" /f" ascii //weight: 1
        $x_1_5 = "= \"www\";" ascii //weight: 1
        $x_1_6 = "= \"com.br\";" ascii //weight: 1
        $x_1_7 = "= \"b.br\";" ascii //weight: 1
        $x_1_8 = "+\".credicard.\"+" ascii //weight: 1
        $x_1_9 = "+\".santanderbanespa.\"+" ascii //weight: 1
        $x_1_10 = "+\".serasaexperian.\"+" ascii //weight: 1
        $x_1_11 = "+\".bancodobrasil.\"+" ascii //weight: 1
        $x_1_12 = "if ((host == \"santander." ascii //weight: 1
        $x_1_13 = "attrib +H \"%appdata%\"\\!z!" ascii //weight: 1
        $x_1_14 = "key=HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banker_L_2147655993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker.L"
        threat_id = "2147655993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 8b 43 fc 03 46 fc a9 00 00 00 c0 75 ?? e8 ?? ?? ?? ?? 89 c7 89 fa 89 d8 8b 4b fc d1 e1 e8 ?? ?? ?? ?? 89 f0 8b 4e fc d1 e1 8b 53 fc d1 e2 01 fa e8 ?? ?? ?? ?? 58 89 fa 85 ff 74 ?? ff 4f f8 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "praquem=magaoxx@gmail.com" wide //weight: 1
        $x_1_3 = "magaoxx@ig.com.br" wide //weight: 1
        $x_1_4 = "www.chuanli.com.my" wide //weight: 1
        $x_1_5 = "banco" ascii //weight: 1
        $x_1_6 = "senha" ascii //weight: 1
        $x_1_7 = {8b 44 24 04 8b 77 fc e8 4f fe ff ff 8b 7c 24 04 8b 07 89 04 24 d1 e6 03 37 4b eb 0a e8 ca f1 ff ff 89 04 24 89 c6 8b 44 9c 1c 89 f2 85 c0 74 0c 8b 48 fc d1 e1 01 ce e8 97 ce ff ff 4b 75 e7 8b 14 24 8b 44 24 04 85 ff 75 0c 85 d2 74 03 ff 4a f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Banker_VB_2147678774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker.VB"
        threat_id = "2147678774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 68 00 6f 00 73 00 74 00 34 00 38 00 2e 00 6e 00 65 00 74 00 2f 00 [0-32] 2f 00 74 00 6a 00 2e 00 68 00 74 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "/tmall_new.php?pid=mm_" wide //weight: 1
        $x_1_3 = "&commend=all&pid=mm_" wide //weight: 1
        $x_1_4 = "/pids.txt" wide //weight: 1
        $x_1_5 = {0a 00 53 63 72 69 70 74 6c 65 74 31}  //weight: 1, accuracy: High
        $x_1_6 = {26 00 74 00 61 00 62 00 3d 00 6d 00 61 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {26 00 6d 00 6f 00 64 00 65 00 3d 00 38 00 36 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Banker_U_2147685074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker.U"
        threat_id = "2147685074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 68 02 00 00 00 bb 6c 02 00 00 e8 ?? ?? ?? ?? 83 c4 1c 8b 5d f0 85 db 74 ?? 53 e8 ?? ?? ?? ?? 83 c4 04 68 04 00 00 80 6a 00 68 3e 99 40 00 68 01 00 00 00 bb 98 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6b 6f 72 65 61 63 69 74 69 64 69 72 65 63 74 2e 63 69 74 69 67 72 6f 75 70 2e 63 6f 4d 0d 0a [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 20 6b 42 73 74 61 72 2e 63 6f 4d 0d 0a [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 20 77 77 77 2e 6b 42 73 74 61 72 2e 63 6f 4d}  //weight: 1, accuracy: Low
        $x_1_3 = {4f 70 65 6e 2e 6b 42 73 74 61 72 2e 63 6f 4d 0d 0a [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 20 6f 6d 6f 6e 65 79 2e 6b 42 73 74 61 72 2e 63 6f 4d 0d 0a [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 20 6f 42 61 6e 6b 2e 6b 42 73 74 61 72 2e 63 6f 4d}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 2e 2e 2e 2e 5c 00 5c 2e 2e 2e 2e 5c 54 65 6d 70 6f 72 61 72 79 46 69 6c 65 00 5c 54 65 6d 70 6f 72 61 72 79 46 69 6c 65}  //weight: 1, accuracy: High
        $x_1_5 = {49 8d 44 11 ff 3b c2 72 25 8a 08 80 f9 20 74 0a 80 f9 a1 75 15 38 48 ff 75 10 84 c9 7d 05 83 e8 02 eb 01 48 3b c2 73 e1 eb 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banker_Z_2147694661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker.Z"
        threat_id = "2147694661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Brasil.exe" ascii //weight: 1
        $x_1_2 = {42 00 6f 00 72 00 6c 00 61 00 6e 00 64 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 [0-16] 46 00 69 00 6c 00 65 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 [0-8] 31 00 2e 00 30 00 2e 00 30 00 2e 00 30 00}  //weight: 1, accuracy: Low
        $x_1_3 = "TMethodImplementationIntercept" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banker_AF_2147697250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker.AF"
        threat_id = "2147697250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bf 01 00 00 00 8b 45 f0 0f b7 5c 78 fe 33 5d e0 3b 5d e4 7f 0b 81 c3 ff 00 00 00 2b 5d e4 eb 03}  //weight: 1, accuracy: High
        $x_1_2 = "netsh firewall set opmode enable" wide //weight: 1
        $x_1_3 = "121AE933C65DA3B0778187" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Banker_AG_2147705765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker.AG"
        threat_id = "2147705765"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gbpinj.dll" wide //weight: 1
        $x_1_2 = " - Google Chrome" wide //weight: 1
        $x_1_3 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "{ENTER}" wide //weight: 1
        $x_1_5 = "|REQUESTKEYBOARD|" wide //weight: 1
        $x_1_6 = "Caixa - A vida pede mais que um banco" wide //weight: 1
        $x_1_7 = "Banco Bradesco | Pessoa F" wide //weight: 1
        $x_1_8 = "Banco Ita? - Feito Para Voc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Banker_S_2147730436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker.S!MTB"
        threat_id = "2147730436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&inforuser=" wide //weight: 1
        $x_1_2 = "screenshot.jpg" wide //weight: 1
        $x_1_3 = "Depositar Bitcoin" wide //weight: 1
        $x_1_4 = "card-number" wide //weight: 1
        $x_1_5 = "card-expiration-month" wide //weight: 1
        $x_1_6 = "owner-document-number" wide //weight: 1
        $x_1_7 = "card-expiration-year" wide //weight: 1
        $x_1_8 = "\\SOFTWARE\\Microsoft\\Internet Explorer\\Low Rights\\ElevationPolicy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banker_RA_2147761892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker.RA!MTB"
        threat_id = "2147761892"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 83 fa 08 7c 34 00 8b c6 81 c6 ?? ?? ?? ?? 35 ?? ?? ?? ?? 69 c8 ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 8b c1 c1 e8 0d 33 c1 69 c8 ?? ?? ?? ?? 8b c1 c1 e8 0f 33 c1 89 84 94}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banker_AMK_2147787114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker.AMK!MTB"
        threat_id = "2147787114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {88 44 24 01 80 44 24 01 95 8a 44 24 01 08 44 24 02 8a 44 24 03 30 44 24 02 fe 44 24 03 8a 44 24 02 88 04 0b}  //weight: 10, accuracy: High
        $x_10_2 = {8b 04 24 01 d8 69 c0 75 da 81 64 89 04 24 8b 04 24 01 d8 69 c0 75 da 81 64 89 04 24}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banker_RPB_2147807734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker.RPB!MTB"
        threat_id = "2147807734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 c7 14 cb 88 01 8b 54 24 10 6b ce 27 89 38 8b c2 2b c1 2b c3 83 c0 04 8d 88 3f ff ff ff 03 ce 81 f9 0e 1d 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banker_ARE_2147899445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker.ARE!MTB"
        threat_id = "2147899445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 05 2b d0 8b c2 c3}  //weight: 1, accuracy: High
        $x_1_2 = {c6 03 e8 8d 56 04 8b c3 e8 ?? ?? ?? ?? 89 43 01 8b 07 89 43 05 89 1f 83 c3 0d 8b c3 2b c6 3d fc 0f 00 00 7c db}  //weight: 1, accuracy: Low
        $x_1_3 = "c:\\china-drm\\tempf\\" ascii //weight: 1
        $x_1_4 = "cmd.exe /c net start Spooler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banker_ARG_2147899446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker.ARG!MTB"
        threat_id = "2147899446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c0 05 2b d0 8b c2 c3}  //weight: 2, accuracy: High
        $x_2_2 = {c6 03 e8 8d 56 04 8b c3 e8 ?? ?? ?? ?? 89 43 01 8b 07 89 43 05 89 1f 83 c3 0d 8b c3 2b c6 3d fc 0f 00 00 7c db}  //weight: 2, accuracy: Low
        $x_1_3 = "NetWkstaGetInfo" ascii //weight: 1
        $x_3_4 = "Extreme Injector.exe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banker_MV_2147906179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker.MV!MTB"
        threat_id = "2147906179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wdproton" ascii //weight: 1
        $x_1_2 = {a1 64 a6 45 00 a3 6c 8d 45 00 68 5c 8d 45 00 e8 34 52 fb ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banker_RHA_2147912667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker.RHA!MTB"
        threat_id = "2147912667"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SANTANDER" wide //weight: 1
        $x_1_2 = "Sicoobnet" wide //weight: 1
        $x_1_3 = "Snh Card" wide //weight: 1
        $x_1_4 = "BANCO DO BRASIL" wide //weight: 1
        $x_1_5 = "Username" wide //weight: 1
        $x_1_6 = "Password" wide //weight: 1
        $x_1_7 = "START-CAPTURA" wide //weight: 1
        $x_1_8 = "STOP-CAPTURA" wide //weight: 1
        $x_1_9 = "APP-HIDE" wide //weight: 1
        $x_1_10 = "CreateToolhelp32Snapshot" wide //weight: 1
        $x_1_11 = "Module32NextW" wide //weight: 1
        $x_1_12 = "listen" wide //weight: 1
        $x_1_13 = "WSAASyncGetServByName" wide //weight: 1
        $x_2_14 = {50 45 00 00 4c 01 0a ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 02 19 00 ?? 28 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banker_EM_2147932894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker.EM!MTB"
        threat_id = "2147932894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {89 45 f4 c6 45 ee e9 8a 45 f4 88 45 ef 8b 45 f4 c1 e8 08 88 45 f0 8b 45 f4 c1 e8 10 88 45 f1 8b 45 f4 c1 e8 18 88 45 f2 c6 45 f3 c3}  //weight: 3, accuracy: High
        $x_1_2 = "filiation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banker_MBS_2147934924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker.MBS!MTB"
        threat_id = "2147934924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {36 35 34 36 34 35 72 72 72 72 40 6d 61 69 6c 2e 72 75 00 37 36 37 38 37 6a 68 6a 68 40 6d 61 69 6c 2e 72 75 00 73 6d 74 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banker_16459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker"
        threat_id = "16459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\pidfenon.dll" ascii //weight: 5
        $x_5_2 = "\\paruisd.dll" ascii //weight: 5
        $x_5_3 = "{C8A3B994-E27A-42f5-A053-C63799E621FB}" ascii //weight: 5
        $x_3_4 = "{A38728A6-63D9-43ee-BF7F-1BCE6086191F}" ascii //weight: 3
        $x_2_5 = "Software\\MRSoft" ascii //weight: 2
        $x_2_6 = "RITLAB.1" ascii //weight: 2
        $x_1_7 = ">> NUL" ascii //weight: 1
        $x_1_8 = "/c del " ascii //weight: 1
        $x_1_9 = "\\conf.dat" ascii //weight: 1
        $x_1_10 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Banker_16459_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker"
        threat_id = "16459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\Archivos de programa\\Messenger\\msmsgs.exe" ascii //weight: 10
        $x_10_2 = "\\system32\\drivers\\etc\\hosts.pre" wide //weight: 10
        $x_1_3 = "banamex.com" wide //weight: 1
        $x_1_4 = "banamex.com.mx" wide //weight: 1
        $x_1_5 = "boveda.banamex.com.mx" wide //weight: 1
        $x_1_6 = "bancanetempresarial.banamex.com.mx" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banker_16459_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banker"
        threat_id = "16459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "184"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "C:\\Arquivos de programas\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 100
        $x_10_2 = "Internet Banking CAIXA - Microsoft Internet Explorer" wide //weight: 10
        $x_10_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 10
        $x_10_4 = "https://www2.bancobrasil.com.br/" wide //weight: 10
        $x_10_5 = "internetcaixa.caixa.gov.br" wide //weight: 10
        $x_10_6 = "https://bankline.itau.com.br/" wide //weight: 10
        $x_10_7 = "Banco.....................: Banco do Brasil" wide //weight: 10
        $x_10_8 = "Content-Type: multipart/mixed; boundary=NextMimePart" wide //weight: 10
        $x_1_9 = "ProjetoFucapi" ascii //weight: 1
        $x_1_10 = "svhootss" ascii //weight: 1
        $x_1_11 = "GOD DAMNIT, the internet doesn't work" wide //weight: 1
        $x_1_12 = "If wVersion == 257 then everything is kewl" wide //weight: 1
        $x_1_13 = "@yahoo.com" wide //weight: 1
        $x_1_14 = "Nacional!" wide //weight: 1
        $x_1_15 = "C:\\WINDOWS\\Downloaded Program Files\\*.gpc" wide //weight: 1
        $x_1_16 = "C:\\WINDOWS\\Downloaded Program Files\\*.gmd" wide //weight: 1
        $x_1_17 = "C:\\WINDOWS\\Downloaded Program Files\\*.dll" wide //weight: 1
        $x_1_18 = "C:\\WINDOWS\\Downloaded Program Files\\*.inf" wide //weight: 1
        $x_1_19 = "C:\\WINDOWS\\tasks\\start.job" wide //weight: 1
        $x_1_20 = "k34lupatop@k1r.com.br" wide //weight: 1
        $x_1_21 = "Norton AntiVirus" wide //weight: 1
        $x_1_22 = "Local do CertificadoKEY.:" wide //weight: 1
        $x_1_23 = "Norton Recebeu 1 - SMTP" wide //weight: 1
        $x_1_24 = "svhootss.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 7 of ($x_10_*) and 14 of ($x_1_*))) or
            (all of ($x*))
        )
}

