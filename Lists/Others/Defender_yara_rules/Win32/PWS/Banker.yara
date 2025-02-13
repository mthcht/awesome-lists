rule PWS_Win32_Banker_B_2147623522_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Banker.B"
        threat_id = "2147623522"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "81"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "Indy 9.00.10" ascii //weight: 10
        $x_10_3 = "MAIL FROM:<" ascii //weight: 10
        $x_10_4 = "smtp.isbt.com.br" ascii //weight: 10
        $x_10_5 = "Cetelem - Banking" ascii //weight: 10
        $x_10_6 = "[3 Digitos]..." ascii //weight: 10
        $x_10_7 = "Validade..." ascii //weight: 10
        $x_10_8 = "=-PINA-2009 vem carioooo-=" ascii //weight: 10
        $x_1_9 = "festadocolono1@isbt.com.br" ascii //weight: 1
        $x_1_10 = "thalixinhainvia@isbt.com.br" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Banker_A_2147640323_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Banker.A"
        threat_id = "2147640323"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Windows\\IME" ascii //weight: 1
        $x_1_2 = "w.163.com.z1.rqbao.com" ascii //weight: 1
        $x_1_3 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 51 00 51 00 4d 00 75 00 73 00 69 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_2_4 = {49 43 42 43 00 00 00 00 ff ff ff ff 03 00 00 00 43 4d 42 00 ff ff ff ff 03 00 00 00 43 43 42 00 ff ff ff ff 03 00 00 00 42 4f 43}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Banker_D_2147645766_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Banker.D"
        threat_id = "2147645766"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Santander" ascii //weight: 1
        $x_1_2 = "GetMonitorInfo" ascii //weight: 1
        $x_1_3 = "AutoConnect@IH" ascii //weight: 1
        $x_2_4 = "infect.php" ascii //weight: 2
        $x_2_5 = {35 ae ca 7b c3 ff 25 ?? ?? ?? ?? 8b c0 53 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 1c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Banker_G_2147647735_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Banker.G"
        threat_id = "2147647735"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 ae ca 7b c3 ff 25 ?? ?? ?? ?? 8b c0 53 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 1c}  //weight: 1, accuracy: Low
        $x_1_2 = "Insira corretamente o campo solicitado" ascii //weight: 1
        $x_1_3 = "digo que aparece em seu visor do seu iToken" ascii //weight: 1
        $x_1_4 = "Token Novo" ascii //weight: 1
        $x_1_5 = ".php" ascii //weight: 1
        $x_1_6 = "hotmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Banker_L_2147649347_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Banker.L"
        threat_id = "2147649347"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b f0 8b d3 8b c6 8b 08 ff 51 08 c6 46 3f 28}  //weight: 3, accuracy: High
        $x_1_2 = "imgbtnClick" ascii //weight: 1
        $x_1_3 = "windows\\temp.jpg" ascii //weight: 1
        $x_1_4 = "USER %s@%s@%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Banker_M_2147649640_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Banker.M"
        threat_id = "2147649640"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Santander" ascii //weight: 1
        $x_1_2 = "key2010" ascii //weight: 1
        $x_1_3 = {8b 00 80 78 57 01 75 05}  //weight: 1, accuracy: High
        $x_1_4 = "go do iToken invalido." ascii //weight: 1
        $x_2_5 = {35 ae ca 7b c3 ff 25 ?? ?? ?? ?? 8b c0 53 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 1c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Banker_S_2147654139_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Banker.S"
        threat_id = "2147654139"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "xercle.net//sql.php" ascii //weight: 1
        $x_1_2 = "xercles.exe" ascii //weight: 1
        $x_1_3 = "xercle.dll" ascii //weight: 1
        $x_1_4 = "evdat2.dmc" ascii //weight: 1
        $x_1_5 = {8b 55 cc b8 ?? ?? ?? 00 e8 ?? ?? ?? ?? 85 c0 0f 85 ?? ?? 00 00 8d 45 c8 8b d3 e8 ?? ?? ?? ?? 8b 55 c8 b8 ?? ?? ?? 00 e8 ?? ?? ?? ?? 85 c0 75 3a 8d 45 c4 8b d3 e8 ?? ?? ?? ?? 8b 55 c4 b8 c0 42 4d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_Banker_U_2147680128_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Banker.U"
        threat_id = "2147680128"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Windows\\system32\\drivers\\etc\\hosts" wide //weight: 1
        $x_1_2 = ".com.br" wide //weight: 1
        $x_1_3 = "Software\\Borland\\Delphi\\Locales" wide //weight: 1
        $x_1_4 = "/cont/index.php" wide //weight: 1
        $x_1_5 = "Tkiloko" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Banker_UC_2147721100_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Banker.UC!bit"
        threat_id = "2147721100"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 2e 74 78 74 00 00 00 18 00 5b 00 00 00 ff ff ff ff 02 00 00 00 5d 5b 00 00 ff ff ff ff 05 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {35 ae ca 7b c3 ff 25 ?? ?? ?? ?? 8b c0 53 33 db 6a 00 e8 ?? ?? ?? ?? 83 f8 07 75 1c 6a 01 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1}  //weight: 1, accuracy: High
        $x_1_4 = {00 57 49 4e 44 4f 57 53 20 4c 49 56 45 20 4d 45 53 53 45 4e 47 45 52 20 50 41 53 53 57 4f 52 44 53 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 46 49 52 45 46 4f 58 20 20 50 41 53 53 57 4f 52 44 53 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 47 4f 4f 47 4c 45 20 43 48 52 4f 4d 45 20 50 41 53 53 57 4f 52 44 53 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 4f 50 45 52 41 20 50 41 53 53 57 4f 52 44 53 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Banker_UD_2147730158_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Banker.UD!bit"
        threat_id = "2147730158"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 fc 0f b6 54 32 ff 66 33 d3 0f b7 d2 2b d6 33 d6 2b d6 33 d6 88 54 30 ff 43}  //weight: 1, accuracy: High
        $x_1_2 = {8a 44 02 ff 32 d8 33 d2 8a d0 32 9a ?? ?? ?? ?? 32 9a ?? ?? ?? ?? 32 9a ?? ?? ?? ?? 32 9a ?? ?? ?? ?? 32 9a ?? ?? ?? ?? 32 9a ?? ?? ?? ?? 32 c3 8b d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Banker_YA_2147731142_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Banker.YA!MTB"
        threat_id = "2147731142"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CHROME PASSWORDS" ascii //weight: 1
        $x_1_2 = "OPERA PASSWORDS" ascii //weight: 1
        $x_1_3 = "DIALUP/RAS/VPN PASSWORDS" ascii //weight: 1
        $x_1_4 = "\\MicrosoftEdge\\TypedURLs" ascii //weight: 1
        $x_1_5 = "\\Apple Computer\\Preferences\\keychain.plist" ascii //weight: 1
        $x_1_6 = "BEGIN CLIPBOARD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Banker_YB_2147731404_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Banker.YB!MTB"
        threat_id = "2147731404"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"encryptedPassword\":" ascii //weight: 1
        $x_1_2 = "Windows Live Mail IMAP" wide //weight: 1
        $x_1_3 = "Outlook Express POP3" wide //weight: 1
        $x_1_4 = "\\Thunderbird\\%s\\logins.json" ascii //weight: 1
        $x_1_5 = "SELECT displayName FROM AntivirusProduct" wide //weight: 1
        $x_1_6 = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

