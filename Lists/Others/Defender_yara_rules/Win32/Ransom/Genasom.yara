rule Ransom_Win32_Genasom_B_2147599803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.B"
        threat_id = "2147599803"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wl.exe CADOff KeysOff MouseOff" ascii //weight: 1
        $x_3_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 62 61 63 6b 64 6f 6f 72 2d 67 75 61 72 64 2e 63 6f 6d 2f 69 6e 64 65 78 2e 70 68 70 3f 6d 6f 64 75 6c 65 3d 70 61 79 26 6d 73 67 3d 77 69 6e 26 75 69 64 3d 00 70 73 6b 69 6c 6c 2e 65 78 65 20 2f 61 63 63 65 70 74 65 75 6c 61 20 77 6c 2e 65 78 65 00 00 00 70 73 6b 69 6c 6c 2e 65 78 65 20 2f 61 63 63 65 70 74 65 75 6c 61 20 69 65 78 70 6c 6f 72 65 2e 65 78 65}  //weight: 3, accuracy: High
        $x_1_3 = {69 6e 73 74 61 6c 6c 00 6f 74 73 74 75 6b 2e 62 61 74}  //weight: 1, accuracy: High
        $x_1_4 = {62 61 63 6b 64 6f 6f 72 20 63 68 65 63 6b 00 00 ff ff ff ff 07 00 00 00 69 6e 73 74 61 6c 6c}  //weight: 1, accuracy: High
        $x_1_5 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 00 00 ff ff ff ff 03 00 00 00 52 75 6e 00 ff ff ff ff 07 00 00 00 4c 69 63 65 6e 73 65 00 ff ff ff ff 0a 00 00 00 6c 6f 63 6b 65 72 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Genasom_D_2147625613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.D"
        threat_id = "2147625613"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3f 75 63 6f 64 65 3d 00 43 6f 6f 6b 69 65 00 00 4d 65 64 69 61 56 69 65 77 00 00 00 52 65 67 69 73 74 54 00 52 65 67 69 73 74 44 00 52 65 67 69 73 74 49 44}  //weight: 1, accuracy: High
        $x_1_2 = "Software\\KJ\\Share\\DateInfo\\Wareki\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_F_2147626080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.F"
        threat_id = "2147626080"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b2 65 6a 00 b3 5c 51 88 54 24 ?? 88 54 24 ?? 88 54 24 ?? 88 54 24 ?? 88 54 24 ?? 88 54 24 ?? 8b 15 ?? ?? 40 00 68 01 00 00 80 c6 44 24 ?? 53 c6 44 24 ?? 66 c6 44 24 ?? 74 c6 44 24 ?? 77 c6 44 24 ?? 61}  //weight: 1, accuracy: Low
        $x_1_2 = {5c c6 44 24 ?? 52 c6 44 24 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_H_2147626953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.H"
        threat_id = "2147626953"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 61 64 75 6c 74 66 61 6b 65 2e 72 75 2f 6d 65 6d 62 65 72 73 2e 70 68 70 00 6f 70 65 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {75 6e 69 78 74 69 6d 65 2e 64 61 74 00 00 00 00 5c 00 00 00 6c 6e 6b 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_N_2147629032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.N"
        threat_id = "2147629032"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "activate.exe" ascii //weight: 1
        $x_1_2 = "DisableTaskMgr" ascii //weight: 1
        $x_1_3 = {8b 45 10 8b 48 04 49 83 e9 0b 72 05 83 38 08 75 09 83 38 1b 74 04 33 c0 eb 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_O_2147629310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.O"
        threat_id = "2147629310"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 10, accuracy: High
        $x_10_2 = {5f 00 69 00 6d 00 61 00 63 00 [0-2] 4a 00 46 00 59 00 44 00 45 00 4b 00 52 00 34 00 37 00 48 00 45 00}  //weight: 10, accuracy: Low
        $x_1_3 = "afterBegin" wide //weight: 1
        $x_1_4 = "Flags" wide //weight: 1
        $x_1_5 = "microsoft.data.xsl" wide //weight: 1
        $x_1_6 = "mediamodule.xsl" wide //weight: 1
        $x_1_7 = "\\Microsoft\\Windows\\CurrentVersion\\Ext\\Settings" wide //weight: 1
        $x_1_8 = "eval(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Genasom_Q_2147630509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.Q"
        threat_id = "2147630509"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "13616" wide //weight: 1
        $x_1_2 = {69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "locker - new\\toSEND\\form.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_V_2147631109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.V"
        threat_id = "2147631109"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {34 cd 66 0f b6 c0 41 66 89 02 8a 01 83 c2 02 3c cd 75 ed 33 c9}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 01 66 83 f8 2a 74 06 66 89 02 83 c2 02 83 c1 02 66 83 39 00 75 e8}  //weight: 1, accuracy: High
        $x_1_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 78 73 74 6f 70 69 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_W_2147631110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.W"
        threat_id = "2147631110"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 3b 00 00 00 ?? 2b ?? 53 c6 84 24 ?? ?? 00 00 e8 04 00 6a 05}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 00 41 c6 40 01 64 c6 40 02 6a c6 40 03 75 c6 40 04 73 c6 40 05 74 c6 40 06 54 c6 40 07 6f c6 40 08 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_Y_2147631320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.Y"
        threat_id = "2147631320"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a ff 6a fe 6a ff ff 15 ?? ?? ?? ?? 8b 86 ?? 00 00 00 3b c3 74 0e 53 53 68 b1 04 00 00 50}  //weight: 1, accuracy: Low
        $x_1_2 = {7c 3a 8b 44 24 0c 6a 01 83 c0 2c 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 84 c0 74 21 53 53 53 68 ?? ?? ?? ?? 53 53 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = "ffffffff-F03B-4b40-A3D0-F62E04DD1C09" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_Z_2147631490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.Z"
        threat_id = "2147631490"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 6a 1a 53 ff 15 ?? ?? ?? ?? 85 c0 7c 7e 68 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 85 c0 74 68 53 6a 02 6a 02 53 53 6a 02}  //weight: 1, accuracy: Low
        $x_1_2 = {49 45 44 61 74 61 46 65 65 64 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = "mediamodule.xsl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_AC_2147632204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.AC"
        threat_id = "2147632204"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ce code d'acces vous permet d'utiliser nos connexion premium afin d'obtenir la meilleure vitesse de telechargement possible" ascii //weight: 1
        $x_1_2 = "http://gw.netlinkinvest.com/checkcode.php" ascii //weight: 1
        $x_1_3 = "&document=openoffice.2010-fr." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_AD_2147632208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.AD"
        threat_id = "2147632208"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "unlock your computer" ascii //weight: 100
        $x_10_2 = "/buy_soft.php?productid=PERSPRT_1&advert=" wide //weight: 10
        $x_10_3 = "/buy2.php?affid=40500&sts=" wide //weight: 10
        $x_1_4 = "WARNING WINDOWS SECURITY CENTER" ascii //weight: 1
        $x_1_5 = "YOUR COMPUTER IS INFECTED BY SPYWARE !!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Genasom_AJ_2147632921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.AJ"
        threat_id = "2147632921"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 66 69 72 65 66 6f 78 2e 65 78 65 22}  //weight: 1, accuracy: High
        $x_1_2 = {00 6f 70 65 72 61 2e 65 78 65 22}  //weight: 1, accuracy: High
        $x_1_3 = "reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\run\" " ascii //weight: 1
        $x_1_4 = "Software\\WebMoney\\path" ascii //weight: 1
        $x_1_5 = "sms-price.ru" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_AN_2147633888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.AN"
        threat_id = "2147633888"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://%s/_req/?type=%c&sid=%d&sw=" ascii //weight: 2
        $x_1_2 = "avastsvc.exe" ascii //weight: 1
        $x_3_3 = "&ostype=%d&ossp=%d&osbits=%d&osfwtype=%d&osrights=" ascii //weight: 3
        $x_3_4 = "support.kaspersky.ru/viruses/deblocker" ascii //weight: 3
        $x_1_5 = "PC Health Status" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Genasom_AP_2147634092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.AP"
        threat_id = "2147634092"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 00 35 00 33 00 36 00 25 00 64 00 00 00 00 00 39 00 35 00 33 00 37 00 25 00 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {34 00 36 00 33 00 37 00 25 00 64 00 00 00 00 00 34 00 36 00 33 00 38 00 25 00 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {33 00 33 00 38 00 31 00 00 00 00 00 49 00 45 00 58 00 50 00 4c 00 4f 00 52 00 45 00 2e 00 45 00 58 00 45 00}  //weight: 1, accuracy: High
        $x_10_4 = {74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 00 00 72 00 65 00 67 00 65 00 64 00 69 00 74 00 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: High
        $x_10_5 = {6d 00 73 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 65 00 78 00 65 00 00 00 00 00 74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 49 00 4d 00}  //weight: 10, accuracy: High
        $x_10_6 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 49 00 4d 00 [0-64] 25 00 55 00 53 00 45 00 52 00 50 00 52 00 4f 00 46 00 49 00 4c 00 45 00 25 00 5c 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 5c 00 2a 00 2e 00 2a 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Genasom_AS_2147634369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.AS"
        threat_id = "2147634369"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attrib +H \"C:\\Documents and Settings\\All Users\\" ascii //weight: 1
        $x_1_2 = "reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\run\" /v Shell /t REG_SZ /d" ascii //weight: 1
        $x_1_3 = "mover.bat" ascii //weight: 1
        $x_1_4 = "config.bat" ascii //weight: 1
        $x_1_5 = "hide.bat" ascii //weight: 1
        $x_1_6 = "moving.bat" ascii //weight: 1
        $x_2_7 = "prefetching.txt" ascii //weight: 2
        $x_2_8 = "delock.txt" ascii //weight: 2
        $x_2_9 = "pornhub.com" ascii //weight: 2
        $x_3_10 = {ff da 00 0c 03 01 00 02 11 03 11 00 3f 00 fb 9b f6 35 fd 8d be 0d eb df b1 b7 c1 dd 47 51 f8 3b f0 97 52 d4 75 2f 01 e8 17 97 97 97 9e 0c d3 2e}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Genasom_AW_2147636365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.AW"
        threat_id = "2147636365"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "echo>\"kasper_zaebal.exe:Zone.Identifier" wide //weight: 1
        $x_1_2 = {6b 00 61 00 76 00 70 00 2e 00 62 00 61 00 74 00 [0-48] 6d 00 6f 00 76 00 65 00 20 00 61 00 76 00 70 00 2e 00 65 00 78 00 65 00 20 00 61 00 76 00 70 00 2e 00 65 00 78 00 5f 00}  //weight: 1, accuracy: Low
        $x_1_3 = "redtube.eu/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Genasom_AZ_2147636668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.AZ"
        threat_id = "2147636668"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 63 72 00 65 65 6e 2e 6a 70 67 [0-6] 45 78 70 6c 6f 72 65 00 72 20 68 74 74 70 3a 2f 00 2f [0-16] 2e 50 6e 65 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_BC_2147637774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.BC"
        threat_id = "2147637774"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 65 6c 20 22 00 22 20 3e 3e 20 4e 55 4c 00 74 65 6d 70 73 79 73 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {e8 f2 e5 20 e2 20 53 4d 53 20 ed e0 20 f3 ea e0}  //weight: 1, accuracy: High
        $x_1_3 = "pornhub.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Genasom_BH_2147638426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.BH"
        threat_id = "2147638426"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_3_2 = "C:\\WINDOWS\\system32\\xxx_video.exe" ascii //weight: 3
        $x_1_3 = "C:\\windows\\system32\\taskmgr.exe" ascii //weight: 1
        $x_1_4 = "Shell_TrayWnd" ascii //weight: 1
        $x_2_5 = "Timer1Timer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Genasom_BI_2147638528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.BI"
        threat_id = "2147638528"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AVVISO PRELIMINARE: PER OGNI CHIAMATA DI SESSANTA SECONDI AL NUMERO 899022292, ALL'UTENTE DEL TELEFONO CELLULARE VERR" ascii //weight: 1
        $x_1_2 = "ADEBITATO UN IMPORTO DI SEIS E DIVIANNOVE EURO (IVA INCLUSA)." ascii //weight: 1
        $x_1_3 = "www.netlinkinvest.com/support/it" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_BO_2147640540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.BO"
        threat_id = "2147640540"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 49 43 52 4f 53 4f 46 54 20 53 59 53 54 45 4d 20 53 45 43 55 52 49 54 59 00}  //weight: 1, accuracy: High
        $x_1_2 = {6f 00 62 00 6a 00 5f 00 45 00 44 00 49 00 54 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {27 00 6d 00 79 00 6e 00 75 00 6d 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {66 81 7f 04 05 b0 75 73 51 0f b7 4f 0a 8b 73 4c 66 3b 4e 20 75 1b 80 bb 26 01 00 00 00 7f 4e 89 d8 b2 01 e8 ?? ?? ff ff 89 d8 e8 ?? ?? 00 00 eb 3c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Genasom_C_2147640541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.gen!C"
        threat_id = "2147640541"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 43 61 70 74 69 6f 6e 00 [0-32] 30 48 30 20 3e 3f 35 40 30 46 38 3e 3d 3d 30 4f 20 41 38 41 42 35 3c 30 20 37 30 31 3b 3e 3a 38 40 3e 32 30 3d 30 20 37 30 20 3d 30 40 43 48 35 3d 38 35 20 38 41 3f 3e 3b 4c 37 3e 32 30 3d 38 4f 20 41 35 42 38 20 38 3d 42 35 40 3d 35 42 2e}  //weight: 1, accuracy: Low
        $x_1_2 = {d1 8f 20 62 69 6f 73 2c 20 57 69 6e 64 6f 77 73}  //weight: 1, accuracy: High
        $x_1_3 = {38 2d 39 36 37 2d 32 38 34 2d 37 34 2d 34 37 06 0f 38 2d 39 36 33 2d 36 36 36 2d 39 39 2d 32 38 06 0f}  //weight: 1, accuracy: High
        $x_1_4 = {53 79 73 74 65 6d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 43 6f 6e 74 72 6f 6c 5c 53 61 66 65 42 6f 6f 74 5c 66 75 63 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 79 73 74 65 6d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 43 6f 6e 74 72 6f 6c 5c 53 61 66 65 42 6f 6f 74 5c 79 6f 75 00}  //weight: 1, accuracy: High
        $x_1_6 = {6a 01 6a 00 6a 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 a1 ?? ?? ?? ?? 8b 00 8b 40 30 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Genasom_BQ_2147640647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.BQ"
        threat_id = "2147640647"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "HOW TO DECRYPT FILES." ascii //weight: 2
        $x_4_2 = "Nobody can help you - even don't try" ascii //weight: 4
        $x_3_3 = "We can help to solve this task for 120$ via wire transfer" ascii //weight: 3
        $x_3_4 = {8b 75 08 8b fe 33 d2 8b 4d 0c 83 fa 10 75 02 33 d2 ac 32 82 ?? ?? 40 00 aa 42 49 75 ed}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Genasom_BR_2147640696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.BR"
        threat_id = "2147640696"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 73 74 61 72 74 69 6e 67 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {6f 62 6a 5f 53 54 41 54 49 43 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 5c 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {4c 42 6f 6d 65 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 42 6f 6d 65 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 42 6f 6d 65 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {0f ba f0 1f 73 09 83 e0 7f 50 e8 ?? ?? ff ff c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Genasom_CE_2147641610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.CE"
        threat_id = "2147641610"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4c 69 63 65 6e 73 65 72 5c 61 61 73 75 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = "taskkill /im" ascii //weight: 1
        $x_1_3 = {5c 53 79 73 74 65 6d 5c 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 53 79 73 74 65 6d 5c 44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {68 04 01 00 00 68 ?? ?? ?? 00 e8 ?? ?? ?? ff 68 ?? ?? ?? 00 68 ?? ?? ?? 00 e8 ?? ?? ?? ff 68 ?? ?? ?? 00 68 ?? ?? ?? 00 e8 ?? ?? ?? ff b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 6a 00 68 ?? ?? ?? 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Genasom_CF_2147641666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.CF"
        threat_id = "2147641666"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ac 0f be c0 50 0f be 4e 02 01 c8 ab 58 50 0f be 0e 01 c8 ab 92 58 83 c0 40 ab 92 83 c0 40 ab 59 8b 81 ?? 00 00 00}  //weight: 4, accuracy: Low
        $x_2_2 = "89030000000" ascii //weight: 2
        $x_2_3 = "mynum" ascii //weight: 2
        $x_2_4 = "mynewip" ascii //weight: 2
        $x_1_5 = "SOFTWARE\\Microsoft\\Internet Explorer" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_7 = "System\\CurrentControlSet\\Control\\SafeBoot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Genasom_CG_2147641755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.CG"
        threat_id = "2147641755"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "8-962-926-76-05" ascii //weight: 1
        $x_1_2 = "8-962-926-76-07" ascii //weight: 1
        $x_1_3 = "8-963-716-30-47" ascii //weight: 1
        $x_1_4 = "8-965-124-76-89" ascii //weight: 1
        $x_1_5 = "8-965-148-91-42" ascii //weight: 1
        $x_1_6 = "8-965-165-64-05" ascii //weight: 1
        $x_1_7 = "8-965-251-77-65" ascii //weight: 1
        $x_1_8 = "8-965-398-62-47" ascii //weight: 1
        $x_1_9 = "8-965-398-62-67" ascii //weight: 1
        $x_1_10 = "8-967-268-98-58" ascii //weight: 1
        $x_2_11 = "kisskiss" ascii //weight: 2
        $x_2_12 = "delete.bat" ascii //weight: 2
        $x_2_13 = {57 69 6e 64 6f 77 73 00 57 69 6e 64 6f 77 73 20 54 61 73 6b 20 4d 61 6e 61 67 65 72}  //weight: 2, accuracy: High
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

rule Ransom_Win32_Genasom_CH_2147641845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.CH"
        threat_id = "2147641845"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://%s/_req/?type=%c&sid=%d&sw=" ascii //weight: 1
        $x_1_2 = "PC Health Status" ascii //weight: 1
        $x_1_3 = "&ostype=%d&ossp=%d&osbits=%d&osfwtype=%d&osrights=" ascii //weight: 1
        $x_1_4 = "avastsvc.exe" ascii //weight: 1
        $x_1_5 = "real-goodporno.info" ascii //weight: 1
        $x_1_6 = "\\Application Data\\scgrbzbw.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_CN_2147642346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.CN"
        threat_id = "2147642346"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 55 f8 8d 45 fc b9 ?? ?? ?? 00 e8 ?? ?? ?? ?? 6a ff 8b 45 fc e8 ?? ?? ?? ?? 50 8d 55 f4 33 c0 e8 ?? ?? ?? ?? 8b 45 f4 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? ba 06 00 00 00 8b 45 fc e8 ?? ?? ?? ?? b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 03 ba 01 00 00 80}  //weight: 5, accuracy: Low
        $x_5_2 = "\\Sound.exe" ascii //weight: 5
        $x_5_3 = "System\\CurrentControlSet\\Control\\SafeBoot\\" ascii //weight: 5
        $x_1_4 = "\\taskmgr.exe" ascii //weight: 1
        $x_1_5 = "\\del.bat" ascii //weight: 1
        $x_1_6 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Genasom_CT_2147643769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.CT"
        threat_id = "2147643769"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4f 45 52 55 45 35 54 38 52 37 46 52 47 42 57 33 34 59 4a 54 52 54 44 46 4e 51 32 00}  //weight: 1, accuracy: High
        $x_1_2 = "%userprofilE%\\" ascii //weight: 1
        $x_1_3 = {c7 85 d8 f2 ff ff 4b 00 65 00 c7 85 dc f2 ff ff 72 00 6e 00 c7 85 e0 f2 ff ff 65 00 6c 00 c7 85 e4 f2 ff ff 33 00 32 00 c7 85 e8 f2 ff ff 2e 00 64 00 c7 85 ec f2 ff ff 6c 00 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_CX_2147644384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.CX"
        threat_id = "2147644384"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 6f 75 6e 64 [0-3] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {73 74 61 72 74 20 6f 75 6e 64 [0-3] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_3_3 = {68 00 04 00 00 8d 44 24 04 50 e8 ?? ?? ?? ?? 8b c3 8b d4 b9 01 04 00 00 e8 ?? ?? ?? ?? 81 c4 04 04 00 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Genasom_DH_2147645378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.DH"
        threat_id = "2147645378"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 72 75 00 00 00 00 48 54 54 50 2f 31 2e 30 00 [0-7] 2f 6c 6f 63 6b 65 72 2e 70 68 70 00 47 45 54 00 [0-5] 55 8b ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_DK_2147645940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.DK"
        threat_id = "2147645940"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 1d 8d 55 f8 8b 83 00 03 00 00 e8 ?? ?? ?? ?? 8b 45 f8 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 75 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 66 83 39 73 75 09 a8 02 74 05 66 c7 01 00 00 a8 02 74 0b 66 83 39 09 75 05}  //weight: 1, accuracy: High
        $x_1_3 = {2f 66 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 00 74 61 73 6b 6b 69 6c 6c 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {f6 45 08 02 74 0b 66 83 39 73 75 05 66 c7 01 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {25 57 69 6e 44 69 72 25 5c 57 69 6e 33 32 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Genasom_DN_2147646282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.DN"
        threat_id = "2147646282"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " /v Userinit /t REG_SZ /d \"%WINDIR%\\system32\\userinit.exe,%userprofile%\\" wide //weight: 1
        $x_1_2 = {ff d3 50 ff d6 68 d0 01 00 00 8d 94 24 ?? ?? 00 00 6a 00 b9 0e 00 00 00 be ?? ?? ?? ?? 8d bc 24 ?? ?? 00 00 52 f3 a5 e8 ?? ?? ?? ?? 83 c4 0c 83 7c 24 10 00 0f 85 ?? ?? 00 00 33 c0 68 06 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_DU_2147647111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.DU"
        threat_id = "2147647111"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 1c 6a 00 6a 20 6a 04 6a 00 6a 01 68 00 00 00 40 52 ff d5 6a 00 8b e8 8d 44 24 14 50 57 53 55 ff}  //weight: 1, accuracy: High
        $x_1_2 = {85 c0 75 4d 6a 01 6a 1a 8d 44 24 0c 50 6a 00 ff}  //weight: 1, accuracy: High
        $x_1_3 = {8d 4c 24 58 51 ff d6 68 e8 b3 40 00 8d 54 24 58 52 ff d6}  //weight: 1, accuracy: High
        $x_1_4 = {8d 44 24 0c 50 ff d3 8d 4c 24 0c 51 ff d5 6a 0a ff 15 ?? ?? ?? 00 6a 00 6a 00 6a 00 8d 54 24 18 52 ff d6 85 c0 75 d9 5d 5b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_DW_2147647253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.DW"
        threat_id = "2147647253"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 3e 3c 3f 78 6d 75 0c 80 7e 04 6c 75 06 80 7e 05 20 74 4d}  //weight: 1, accuracy: High
        $x_1_2 = "Now your computer is blocked by newly installed software" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_DZ_2147647513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.DZ"
        threat_id = "2147647513"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 00 03 40 3c 8b 40 08 0b c0 75 01 c3 6a 00 e8 ?? ?? 01 00 8b d8 6a 10 6a 01 53 e8 ?? ?? 01 00 e9 a2 00 00 00 0d 00 e9 ?? ?? 01 00 68 ?? ?? 42 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "Hyde.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_EJ_2147648351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.EJ"
        threat_id = "2147648351"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 06 53 41 46 5f 8d 85 ?? ?? ff ff 50 e8 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 8d 45 ?? 50 e8 ?? ?? ?? ?? 8d 45 ?? 50 6a 00 6a 00 e8}  //weight: 2, accuracy: Low
        $x_1_2 = "%s\\Identities\\%s\\svghost.exe" ascii //weight: 1
        $x_1_3 = {6a 00 68 00 f7 04 84 6a 00 6a 00 68 ?? ?? ?? ?? ff 75 ?? 68 ?? ?? ?? ?? ff b5 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_4 = {42 00 65 00 7a 00 61 00 68 00 6c 00 65 00 6e 00 20 00 75 00 6e 00 64 00 20 00 72 00 75 00 6e 00 74 00 65 00 72 00 6c 00 61 00 64 00 65 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {6a 09 6a 01 6a ?? ff 75 08 e8 ?? ?? ?? ?? 6a (73|1b) 6a 01 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Genasom_EO_2147648625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.EO"
        threat_id = "2147648625"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "111"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "\\winlock.pdb" ascii //weight: 100
        $x_10_2 = {65 6e 74 65 72 20 74 20 63 6f 64 65}  //weight: 10, accuracy: Low
        $x_1_3 = "+7 911 " ascii //weight: 1
        $x_1_4 = "+7 981 " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Genasom_ES_2147648862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.ES"
        threat_id = "2147648862"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 ff ff 00 00 57 ff 15 ?? ?? ?? ?? 68 54 76 d8 00 57 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {99 2b c2 8b f0 b8 4d 02 00 00 2b 05 ?? ?? ?? ?? d1 fe 99 2b c2 8b f8 d1 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {68 fa 00 00 00 6a 00 ff d5 50 ff 15 ?? ?? ?? ?? 8b f8 85 ff 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_FF_2147649678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.FF"
        threat_id = "2147649678"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 84 05 f1 fe ff ff 3e c6 84 05 f3 fe ff ff 6e c6 84 05 f4 fe ff ff 75 c6 84 05 f5 fe ff ff 6c}  //weight: 1, accuracy: High
        $x_1_2 = {c7 85 a4 fc ff ff 53 65 74 50 c7 85 a8 fc ff ff 72 6f 63 65 c7 85 ac fc ff ff 73 73 50 72 c7 85 b0 fc ff ff 69 6f 72 69 c7 85 b4 fc ff ff 74 79 42 6f c7 85 b8 fc ff ff 6f 73 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {ff ff 54 00 61 00 c7 85 ?? ?? ff ff 73 00 6b 00 c7 85 ?? ?? ff ff 6d 00 67 00 c7 85 ?? ?? ff ff 72 00 2e 00 c7 85 ?? ?? ff ff 65 00 78 00 c7 85 ?? ?? ff ff 65 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {b8 6c 00 00 00 66 89 85 54 fc ff ff b9 6c 00 00 00 66 89 8d 56 fc ff ff ba 20 00 00 00 66 89 95 58 fc ff ff b8 2f 00 00 00 66 89 85 5a fc ff ff b9 46 00 00 00 66 89 8d 5c fc ff ff ba 20 00 00 00 66 89 95 5e fc ff ff b8 2f 00 00 00 66 89 85 60 fc ff ff b9 49 00 00 00 66 89 8d 62 fc ff ff ba 4d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Genasom_FL_2147650637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.FL"
        threat_id = "2147650637"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 00 77 00 65 00 78 00 78 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 [0-16] 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 57 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {39 5e 0c 74 ?? 68 30 75 00 00 ff 15 ?? ?? ?? ?? 8d 4d ?? 51 6a 00 6a 02 ff 15 ?? ?? ?? ?? 8b f8 85 ff 74 ?? 57 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_GG_2147652694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.GG"
        threat_id = "2147652694"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "decodersoft@Safe-mail.net" ascii //weight: 1
        $x_1_2 = {41 4c 4c 45 20 50 45 52 53 d6 4e 4c 49 43 48 45 4e 20 44 41 54 45 4e 20 56 4f 4e 20 49 48 4e 45 4e 20 57 55 52 44 45 4e 20 56 45 52 53 43 48 4c dc 53 53 45 4c 54 21}  //weight: 1, accuracy: High
        $x_1_3 = ".ksr" ascii //weight: 1
        $x_1_4 = "SOLLTE EUER UKASH-CODE IN ORDNUNG SEIN" ascii //weight: 1
        $x_1_5 = {75 2b 8b f8 8b d8 c1 eb 10 81 e7 00 00 ff 00 0b fb 8b d8 81 e3 00 ff 00 00 c1 e0 10 0b d8 c1 ef 08 c1 e3 08 0b fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_GI_2147652786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.GI"
        threat_id = "2147652786"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /F /IM explorer.exe" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_3 = "windowssecurity" ascii //weight: 1
        $x_1_4 = {42 49 4f 53 2c 20 f1 20 ed e5 e2 ee e7 ec ee}  //weight: 1, accuracy: High
        $x_1_5 = {e5 f2 20 ee ef eb e0 f7 e5 ed 2c 20 e2 f1 e5}  //weight: 1, accuracy: High
        $x_1_6 = {31 2e 20 c8 e7 e3 ee f2 ee e2 eb e5 ed e8 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Genasom_GV_2147654056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.GV"
        threat_id = "2147654056"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 f8 10 75 09 80 3d ?? ?? ?? ?? 30 74 13 8b c5 8d 50 01 8a 08 40 3a cb 75 f9 2b c2 83 f8 13 75 0a 6a 40}  //weight: 5, accuracy: Low
        $x_1_2 = "payment validation will take approximately 2-4 hours before you will get access to your system" ascii //weight: 1
        $x_1_3 = "Silence_lock_bot.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_GW_2147654137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.GW"
        threat_id = "2147654137"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 06 6a 01 6a 02 ff 15 e4 20 40 00 6a 02 8b f0 58 68 ?? ?? ?? ?? 66 89 45 f0 ff 15 ?? ?? ?? ?? 6a 50 89 45 f4 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "/n/get.php?pin=" ascii //weight: 1
        $x_1_3 = "/n/get.php?ot=" ascii //weight: 1
        $x_1_4 = "We are processing your payment." ascii //weight: 1
        $x_1_5 = "Silence_lock_bot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Genasom_HE_2147654857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.HE"
        threat_id = "2147654857"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f4 eb 02 eb 10 48 c1 e8 0f c1 e0 0f 0f b7 08 81 e9 4d 5a 00 00 0b c9 75}  //weight: 1, accuracy: High
        $x_1_2 = "\\Silence_lock_bot\\Release\\Silence_lock_bot.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_HI_2147655894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.HI"
        threat_id = "2147655894"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "the1024rsa@i2pmail.org" ascii //weight: 1
        $x_1_2 = "(photos,documents etc.)" ascii //weight: 1
        $x_1_3 = "HOW TO DECRYPT FILES.txt " ascii //weight: 1
        $x_2_4 = {51 57 0f 31 5f 59 25 f0 00 00 00 c1 e8 04 83 c0 61 aa e2 ec}  //weight: 2, accuracy: High
        $x_2_5 = {b9 19 00 00 00 bb 01 00 00 00 d3 e3 23 d8 74 1f 80 c1 41}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Genasom_HS_2147656454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.HS"
        threat_id = "2147656454"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 61 74 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {6b 65 79 2e 72 65 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 64 6f 62 65 52 65 61 64 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System]" ascii //weight: 1
        $x_1_5 = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon]" ascii //weight: 1
        $x_1_6 = "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer]" ascii //weight: 1
        $x_1_7 = "\"DisableLocalMachineRun\"=dword:00000001" ascii //weight: 1
        $x_1_8 = "\"NoFileMenu\"=dword:00000001" ascii //weight: 1
        $x_1_9 = "\"NoControlPanel\"=dword:00000001" ascii //weight: 1
        $x_1_10 = "\"NoDrives\"=dword:3ffffff" ascii //weight: 1
        $x_1_11 = "\"NoClose\"=dword:00000001" ascii //weight: 1
        $x_1_12 = "\"NoChangeStartMenu\"=dword:00000001" ascii //weight: 1
        $x_1_13 = "\"NoViewContextMenu\"=dword:00000001" ascii //weight: 1
        $x_1_14 = "\"NoRun\"=dword:00000001" ascii //weight: 1
        $x_1_15 = "\"NoFind\"=dword:00000001" ascii //weight: 1
        $x_1_16 = "\"NoDesktop\"=dword:00000001" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_HV_2147656658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.HV"
        threat_id = "2147656658"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bootstat.dat" ascii //weight: 2
        $x_2_2 = "netsh.exe" ascii //weight: 2
        $x_2_3 = "pure basic" ascii //weight: 2
        $x_3_4 = "C:\\Serl_log.txt" ascii //weight: 3
        $x_4_5 = "3423434534512333466576743532423423545657567657465345345234234" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_JD_2147658729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.JD"
        threat_id = "2147658729"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "53"
        strings_accuracy = "High"
    strings:
        $x_50_1 = {ff 52 58 6a 00 8b 45 e0 50 8b 4d e0 8b 11 ff 52 60 8b 45 f4 50 8b 4d e0 51 8b 55 e0 8b 02 ff 50 68 8b 4d f8 51 8b 55 e0 52 8b 45 e0 8b 08 ff 51 70}  //weight: 50, accuracy: High
        $x_1_2 = "Die Zahlung per Ukash begleichen" ascii //weight: 1
        $x_1_3 = "pornografischen Inhalten" ascii //weight: 1
        $x_1_4 = "Es wurden auch Emails in Form von Spam,mit terroristischen" ascii //weight: 1
        $x_1_5 = "Ukash d&rsquo;un montant de 100 euros" ascii //weight: 1
        $x_1_6 = "du contenu pornographique aix&eacute;s" ascii //weight: 1
        $x_1_7 = "du SPAM de tendance terroriste" ascii //weight: 1
        $x_1_8 = "MoneyPak of 200$" ascii //weight: 1
        $x_1_9 = "violating Copyright and Related Rights Law" ascii //weight: 1
        $x_1_10 = "Your PC is blocked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Genasom_JJ_2147659609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.JJ"
        threat_id = "2147659609"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "qwerty17_12345" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 00 52 4c 00}  //weight: 1, accuracy: High
        $x_1_3 = {64 6c 6c 00 53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 00 5c 5c 2e 5c 50 48 59 53 49 43 41 4c 44 52 49 56 45 30}  //weight: 1, accuracy: High
        $x_2_4 = {8a 08 40 84 c9 75 ?? 2b c6 8b c8 8d 74 14 ?? 33 c0 f3 a6 74 ?? 1b c0 83 d8 ff 85 c0 0f 84 ?? ?? 00 00 42 81 fa 00 02 00 00 72 ?? 6a 00 6a 00 68 00 02 00 00 53 ff 15 ?? ?? ?? ?? 83 f8 ff}  //weight: 2, accuracy: Low
        $x_3_5 = {ba 80 00 b9 03 00 b8 03 02 bb 00 10 cd 13 73 05 b8 47 0e cd 10 b8 00 11 bd 00 10 b9 40 00 ba c0 00 b7 10 b3 00 cd 10 ba 80 00 b9 05 00 b8 04 02 bb 00 30 cd 13 66 60 b8 01 13 bb 0c 00 b9 30 07 31 d2 bd 00 30 cd 10}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_JU_2147661111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.JU"
        threat_id = "2147661111"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "#32770" ascii //weight: 5
        $x_5_2 = "MTX_SKYPE" ascii //weight: 5
        $x_1_3 = {6a 09 6a 01 6a ?? ff 75 08 e8 ?? ?? ?? ?? 6a (73|1b) 6a 01 6a}  //weight: 1, accuracy: Low
        $x_1_4 = {c6 06 5c c6 46 01 65 c6 46 02 78 c6 46 03 70 c6 46 04 6c c6 46 05 6f c6 46 06 72 c6 46 07 65 c6 46 08 72 c6 46 09 2e c6 46 0a 65 c6 46 0b 78 c6 46 0c 65 c6 46 0d 0a c6 46 0e 0d}  //weight: 1, accuracy: High
        $x_1_5 = {c6 06 5c c6 46 01 75 c6 46 02 73 c6 46 03 65 c6 46 04 72 c6 46 05 69 c6 46 06 6e c6 46 07 69 c6 46 08 74 c6 46 09 2e c6 46 0a 65 c6 46 0b 78 c6 46 0c 65}  //weight: 1, accuracy: High
        $x_1_6 = {c6 06 2e c6 46 01 65 c6 46 02 78 c6 46 03 65 c6 46 04 0a c6 46 05 0d}  //weight: 1, accuracy: High
        $x_1_7 = {6a 09 6a 01 6a 0a ff 75 08 e8 ?? ?? 00 00 6a 73 6a 01 6a 14 ff 75 08 e8 ?? ?? 00 00 6a 1b 6a 01 6a 1e ff 75 08 e8 ?? ?? 00 00 6a 1b 6a 03 6a 28 ff 75 08 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_KF_2147664152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.KF"
        threat_id = "2147664152"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2f 6b 6f 6e 75 2e 70 68 70 3f 68 77 69 64 3d 00}  //weight: 2, accuracy: High
        $x_2_2 = "4GEMA - Auf Ihrem Rechner wurden Raubkopien gefunden" ascii //weight: 2
        $x_1_3 = "\\stnenopmoC dellatsnI\\puteS evitcA\\tfosorciM\\ERAWTFOS" ascii //weight: 1
        $x_1_4 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\ERAWTFOS" ascii //weight: 1
        $x_1_5 = {50 61 67 65 20 69 73 20 6c 6f 61 64 69 6e 67 2c 20 70 6c 65 61 73 65 20 77 61 69 74 2e 20 54 68 69 73 20 6d 61 79 20 74 61 6b 65 20 75 70 20 74 6f 20 33 30 20 73 65 63 6f 6e 64 73 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Genasom_ID_2147667299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.ID"
        threat_id = "2147667299"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 65 74 20 73 74 61 72 74 20 74 65 6c 6e 65 74 00 6e 65 74 20 73 74 61 72 74 20 53 65 72 76 65 72 00 6e 65 74 20 75 73 65 72 20}  //weight: 1, accuracy: High
        $x_1_2 = {64 66 72 67 2e 6d 73 63 2d 00 73 79 73 6b 65 79 00 69 65 78 70 72 65 73 73 00 4e 73 6c 6f 6f 6b 75 70 00 6e 65 74 20 73 68 61 72 65 20 63 24 20 2f 64 65 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {74 73 73 68 75 74 64 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {6e 65 74 20 73 68 61 72 65 20 68 6f 75 6d 65 6e [0-1] 24 3d ?? 3a 5c}  //weight: 1, accuracy: Low
        $x_1_5 = {6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 46 6f 72 62 69 64 64 65 6e 20 2f 61 64 64 00}  //weight: 1, accuracy: High
        $x_1_6 = {2f 61 64 64 00 6e 65 74 20 75 73 65 72 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 20 2f 61 63 74 69 76 65 3a 6e 6f 00}  //weight: 1, accuracy: High
        $x_1_7 = {d4 cb d0 d0 ca b1 b3 f6 b4 ed 21 0d 0a 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_8 = {aa d5 e2 b8 f6 b3 cc d0 f2 c7 eb c8 cf d5 e6 d7 d0 cf b8 d4 c4 b6 c1 d2 d4 cf c2 bc b8 b5 e3 a3}  //weight: 1, accuracy: High
        $x_1_9 = {ac c4 e3 b5 c4 b5 e7 c4 d4 d2 d1 b1 bb ba da bf cd c8 eb c7 d6 c1 cb a3 a1 0d 0a 0d 0a d2 bb a3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Genasom_KT_2147678304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.KT"
        threat_id = "2147678304"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {d0 b4 d0 b5 d0 bd d1 8c d0 b3 d0 b8 2c 20 d0 bf d1 83 d1 82 d0 b5 d0 bc 20 d0 bf d0 b5 d1 80 d0 b5 d1 87 d0 b8 d1 81 d0 bb d0 b5 d0 bd d0 b8 d1 8f 20 d1 81 d1 83 d0 bc d0 bc d1 8b 20 0d 0a d0 b2 d0 b7 d1 8b d1 81 d0 ba d0 b0 d0 bd d0 b8 d1 8f 20 d0 bd d0 b0 20 d0 ba d0 be d1 88 d0 b5 d0 bb d0 b5 d0 ba 20 57 65 62 4d 6f 6e 65 79 20 55}  //weight: 2, accuracy: High
        $x_2_2 = "BehringerX32Administrator" ascii //weight: 2
        $x_1_3 = {53 75 73 70 65 6e 64 4c 61 79 6f 75 74 00 42 65 67 69 6e 49 6e 69 74 00 73 65 74 5f 41 6e 63 68 6f 72 00 67 65 74 5f 4c 69 67 68 74 47 72 61 79 00 73 65 74 5f 42 61 63 6b 43 6f 6c 6f 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {8e c2 94 c2 93 c2 91 c2 92 c2 8a c2 95 c2 95 c2 88 c2 92 c2 92 c2 87 c2 8b c2 8f c2 89 c2 95 c2 88 c2 8f c2 8a 00 55 49 6e 74 33 32 00 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Genasom_KT_2147678304_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.KT"
        threat_id = "2147678304"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "Fire-toll For SEO Masters.exe" ascii //weight: 3
        $x_1_2 = {6c 00 61 00 62 00 65 00 6c 00 31 00 2e 00 54 00 65 00 78 00 74 00 00 [0-8] 6c 00 61 00 62 00 65 00 6c 00 34 00 2e 00 54 00 65 00 78 00 74 00 [0-8] 6c 00 61 00 62 00 65 00 6c 00 35 00 2e 00 54 00 65 00 78 00 74 00 [0-8] 70 00 69 00 63 00 74 00 75 00 72 00 65 00 42 00 6f 00 78 00 33 00 2e 00 42 00 61 00 63 00 6b 00 67 00 72 00 6f 00 75 00 6e 00 64 00 49 00 6d 00 61 00 67 00 65}  //weight: 1, accuracy: Low
        $x_1_3 = {e2 84 96 20 36 35 38 34 35 39}  //weight: 1, accuracy: High
        $x_1_4 = "n=b03f5f7f11d50a3aPADP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Genasom_B_2147719146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.B!bit"
        threat_id = "2147719146"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskMgr" ascii //weight: 2
        $x_4_2 = {aa d5 e2 b8 f6 b3 cc d0 f2 c7 eb c8 cf d5 e6 d7 d0 cf b8 d4 c4 b6 c1 d2 d4 cf c2 bc b8 b5 e3 a3}  //weight: 4, accuracy: High
        $x_1_3 = {6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 [0-32] 2f 61 64 64}  //weight: 1, accuracy: Low
        $x_1_4 = "net user Administrator /active:no" ascii //weight: 1
        $x_1_5 = {6e 65 74 20 75 73 65 72 [0-64] 2f 61 64 64}  //weight: 1, accuracy: Low
        $x_1_6 = {6e 65 74 20 75 73 65 72 [0-64] 2f 61 63 74 69 76 65 3a 79 65 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Genasom_A_2147746064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.A!MTB"
        threat_id = "2147746064"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "taskkill /f /im explorer.exe" ascii //weight: 1
        $x_1_3 = "\\SystemProcess.exe" ascii //weight: 1
        $x_1_4 = "Bloqueo del Sistema" ascii //weight: 1
        $x_1_5 = "Tu sistema ha sido bloqueado" ascii //weight: 1
        $x_1_6 = "SHGetFolderPathA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_C_2147746212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.C!MSR"
        threat_id = "2147746212"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jackpot@jabber.cd (" ascii //weight: 1
        $x_1_2 = "Kaspersky Event Log" ascii //weight: 1
        $x_1_3 = "Doctor Web" ascii //weight: 1
        $x_1_4 = "Symantec Endpoint Protection Client" ascii //weight: 1
        $x_1_5 = "INSTRUCTION.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_BA_2147751912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.BA!MTB"
        threat_id = "2147751912"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 06 83 6c 24 ?? 01 8b 44 24 ?? 85 c0 7d}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 c1 03 05 ?? ?? ?? ?? 25 ff 00 00 00 8a ?? ?? ?? ?? ?? 88 88 ?? ?? ?? ?? 88 96 ?? ?? ?? ?? 0f b6 b0 ?? ?? ?? ?? 0f b6 d2 03 f2 81 e6 ff 00 00 00 81 3d ?? ?? ?? ?? 81 0c 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_SD_2147754143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.SD!MTB"
        threat_id = "2147754143"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "avp.exe" ascii //weight: 1
        $x_1_2 = "\\FILES.txt" ascii //weight: 1
        $x_1_3 = "\\\\.\\pipe\\turum" ascii //weight: 1
        $x_1_4 = "avpui.exe" ascii //weight: 1
        $x_1_5 = {8b 45 08 3b 45 0c 7d ?? b9 01 00 00 00 6b d1 00 0f be 82 ?? ?? ?? ?? 35 ?? ?? 00 00 88 45 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_AR_2147757898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.AR!MTB"
        threat_id = "2147757898"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\GOMER-README.txt" ascii //weight: 10
        $x_10_2 = "\\encryptFiles.pdb" ascii //weight: 10
        $x_10_3 = "gomer.ini" ascii //weight: 10
        $x_1_4 = "%systemdrive%" ascii //weight: 1
        $x_1_5 = "system volume information" ascii //weight: 1
        $x_1_6 = ".gomer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Genasom_MX_2147760556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.MX!MTB"
        threat_id = "2147760556"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " /C timeout /T 15 /NOBREAK && del " wide //weight: 1
        $x_1_2 = "itaskkill /F /T /IM " wide //weight: 1
        $x_1_3 = "alldrivesinfo" wide //weight: 1
        $x_1_4 = "wmic.exe SHADOWCOPY DELETE /nointeractive" wide //weight: 1
        $x_1_5 = "wbadmin DELETE SYSTEMSTATEBACKUP" wide //weight: 1
        $x_1_6 = "wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest" wide //weight: 1
        $x_1_7 = "vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 1
        $x_1_8 = "C:\\Windows\\system32\\vssvc.exe" wide //weight: 1
        $x_1_9 = "-decrypt.hta" wide //weight: 1
        $x_1_10 = "powershell [System.Net.Dns]::GetHostByAddress('" wide //weight: 1
        $x_1_11 = "\\bootmgr" wide //weight: 1
        $x_1_12 = "publicsessionkey" wide //weight: 1
        $x_1_13 = "privatesessionkey" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

rule Ransom_Win32_Genasom_VIS_2147768784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.VIS!MSR"
        threat_id = "2147768784"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 84 18 01 24 0a 00 8b 0d ?? ?? ?? ?? 88 04 19}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 f8 33 45 e0 33 45 f0 2b d8 8b 45 d8 29 45 f4 ff 4d ec 0f 85 12 ff ff ff 8b 45 08 89 78 04 5f 5e 89 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_RF_2147777420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.RF!MTB"
        threat_id = "2147777420"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DEARCRY!" ascii //weight: 1
        $x_1_2 = "readme.txt" ascii //weight: 1
        $x_1_3 = "Your file has been encrypted!" ascii //weight: 1
        $x_1_4 = "C:\\Users\\john\\Documents\\Visual Studio 2008\\Projects\\EncryptFile -svcV2\\Release\\EncryptFile.exe.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_DA_2147779170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.DA!MTB"
        threat_id = "2147779170"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ENCRYPTED BY THE WINTENZZ SECURITY TOOL" ascii //weight: 1
        $x_1_2 = "DECRYPT FILES HERE" ascii //weight: 1
        $x_1_3 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_4 = "Bitcoin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_EA_2147853201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.EA!MTB"
        threat_id = "2147853201"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your documents, photos, databases and other important files have been encrypted!" ascii //weight: 1
        $x_1_2 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_3 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_4 = "wmic shadowcopy delete" ascii //weight: 1
        $x_1_5 = "net stop vss" ascii //weight: 1
        $x_1_6 = "bcdedit /set {default} recoveryenabled no" ascii //weight: 1
        $x_1_7 = "wevtutil clear-log system" ascii //weight: 1
        $x_1_8 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 1
        $x_1_9 = "wevtutil clear-log security" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_AGM_2147917659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.AGM!MTB"
        threat_id = "2147917659"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c5 89 45 fc 56 8b f1 e8 ?? ?? ?? ?? 85 c0 75 47 56 68 14 33 40 00}  //weight: 2, accuracy: Low
        $x_2_2 = {68 24 33 40 00 50 ff 15 ?? ?? ?? ?? 8b f0 83 c4 18 85 f6 74 15 68 28 33 40 00 56}  //weight: 2, accuracy: Low
        $x_1_3 = {0f 10 04 2f 0f 28 ca 0f 57 c8 0f 11 0c 2f 83 c7 10 83 ff 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Genasom_GNS_2147927733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genasom.GNS!MTB"
        threat_id = "2147927733"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 40 00 c4 b3 4d 00 00 00 00 00 2e 3f 41 56 3f 24 63 6c 6f 6e 65 5f 69 6d ?? 6c 40 55 62 61 64 5f}  //weight: 10, accuracy: Low
        $x_1_2 = "Please remove or disable the system debugger before trying to run this program again" ascii //weight: 1
        $x_1_3 = "Your purchase is not complete. Please reattempt payment" ascii //weight: 1
        $x_1_4 = "Your system has been corrected." ascii //weight: 1
        $x_1_5 = "Your license has been removed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

