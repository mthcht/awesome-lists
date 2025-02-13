rule TrojanProxy_Win32_Banker_C_2147648778_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.C"
        threat_id = "2147648778"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {45 78 70 6c 6f 72 65 72 5c 52 75 6e 22 20 2f 76 20 22 50 6f 6c 69 74 63 73 22 20 2f 64 20 43 3a 5c [0-8] 2e 65 78 65}  //weight: 6, accuracy: Low
        $x_3_2 = "praquem=hackinho.cc@" wide //weight: 3
        $x_3_3 = "titulo=[I][N][F][E][C][T]-" wide //weight: 3
        $x_3_4 = "texto=infectado" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Banker_E_2147652862_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.E"
        threat_id = "2147652862"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 61 64 6f 73 20 64 65 20 61 70 6c 69 63 61 74 69 76 6f 73 5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 5c [0-10] 2a 2e 64 65 66 61 75 6c 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 [0-10] (68 74|66 69) 3a 2f 2f [0-80] 2e 03 03 03 03 63 6f 6d 6f 72 67 61 70 69 [0-16] 75 74 6f 43 6f 6e 66 69 67 55 72 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 70 72 65 66 73 2e 6a 73 [0-32] 66 69 72 65 66 6f 78 2e 65 78 65 [0-16] 75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 74 79 70 65 22 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Banker_G_2147654124_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.G"
        threat_id = "2147654124"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "svchosts" ascii //weight: 5
        $x_1_2 = {45 6e 61 62 6c 65 48 74 74 70 31 5f 31 00 [0-16] 50 72 6f 78 79 45 6e 61 62 6c 65 00 [0-16] 4d 69 67 72 61 74 65 50 72 6f 78 79 00}  //weight: 1, accuracy: Low
        $x_1_3 = "ConsentPromptBehaviorAdmin" ascii //weight: 1
        $x_1_4 = ".insidewab.com" ascii //weight: 1
        $x_1_5 = "\\Mozilla\\Firefox\\Profiles\\" ascii //weight: 1
        $x_1_6 = "user_pref(\"network.proxy.autoconfig_url\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Banker_I_2147655485_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.I"
        threat_id = "2147655485"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "mysteryinscarletcity.com//modules/mod_cblogin/mod_cblogin.html" ascii //weight: 100
        $x_20_2 = {5a 50 42 43 5a 44 5f 1b 46 46 5a 4e 4d 1b}  //weight: 20, accuracy: High
        $x_10_3 = {44 47 53 52 46 18 5e 46 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Banker_L_2147655712_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.L"
        threat_id = "2147655712"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Mozilla\\Firefox\\profiles.ini" ascii //weight: 1
        $x_1_2 = {2e 70 61 63 [0-16] 75 73 65 72 5f 70 72 65 66 [0-16] 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 74 79 70 65}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 70 72 65 66 73 2e 6a 73 [0-16] 75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 61 75 74 6f 63 6f 6e 66 69 67 5f 75 72 6c}  //weight: 1, accuracy: Low
        $x_1_4 = "EnableHttp1_1" ascii //weight: 1
        $x_1_5 = "BLR=ATT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Banker_M_2147655722_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.M"
        threat_id = "2147655722"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "170"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "islabonita.be/afbeeldingen/oi.php#reffer" ascii //weight: 100
        $x_50_2 = "dropbox.com/u/" ascii //weight: 50
        $x_50_3 = {41 75 74 6f 43 6f 6e 66 69 67 55 52 4c 00 45 6e 61 62 6c 65 48 74 74 70 31 5f 31 00 50 72 6f 78 79 45 6e 61 62 6c 65}  //weight: 50, accuracy: High
        $x_20_4 = {57 69 6e 64 6f 77 73 20 41 70 70 00 53 4f 46 54 57 41 52 45 5c}  //weight: 20, accuracy: High
        $x_20_5 = "/70573505/winapp.txt" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Banker_O_2147656019_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.O"
        threat_id = "2147656019"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 4c 4f 49 4f 4c 41 25 73 65 74 20 70 61 69 3d 66 75 6e 63 74 69 6f 6e 20 46 69 6e 64 50 72 6f 78 79 46 0d 0a 25 4c 4f 49 4f 4c 41 25 73 65 74 20 69 78 3d 75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Banker_U_2147657032_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.U"
        threat_id = "2147657032"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "310"
        strings_accuracy = "High"
    strings:
        $x_200_1 = "/contact.jsp" wide //weight: 200
        $x_50_2 = "loaders\\PharmingbyeCoLoGy" ascii //weight: 50
        $x_20_3 = "myhousis.net" wide //weight: 20
        $x_20_4 = "amarelinholanches.com.br" wide //weight: 20
        $x_20_5 = "zinteker.com/l-en" wide //weight: 20
        $x_20_6 = "lcd-promotion.com" wide //weight: 20
        $x_20_7 = "globalbrands.nl" wide //weight: 20
        $x_10_8 = "\\Pendencias.com" wide //weight: 10
        $x_5_9 = "unknowsky7@gmail.com" wide //weight: 5
        $x_5_10 = "infects@gmail.com" wide //weight: 5
        $x_5_11 = "bc.mstsc@live.com" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_200_*) and 5 of ($x_20_*) and 2 of ($x_5_*))) or
            ((1 of ($x_200_*) and 5 of ($x_20_*) and 1 of ($x_10_*))) or
            ((1 of ($x_200_*) and 1 of ($x_50_*) and 2 of ($x_20_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_200_*) and 1 of ($x_50_*) and 3 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Banker_V_2147657218_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.V"
        threat_id = "2147657218"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 75 74 6f 43 6f 6e 66 69 67 55 52 4c [0-12] 68 74 74 70 3a 2f 2f 63 6f 6c 65 67 69 6f 62 6f 62 73 2e 63 6f 6d 2f 66 65 6c 69 63 69 64 61 64 65 2f 73 65 63 72 65 74 2e 70 61 63}  //weight: 2, accuracy: Low
        $x_1_2 = "/IM iexplore.exe /F" ascii //weight: 1
        $x_1_3 = "/IM firefox.exe /F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Banker_W_2147657275_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.W"
        threat_id = "2147657275"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {94 ee 83 bd c0 8f b6 02 bf d5 6e fd cc b0 39 5d c8 f8 f6 b7 46 d0 5b c7 aa ce 3d 04 d6 a9 5c 8f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Banker_X_2147657345_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.X"
        threat_id = "2147657345"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 61 6d 70 69 6e 61 73 65 6d 66 6f 63 6f 2e 63 6f 6d 2e 62 72 2f 69 6d 61 67 65 73 2f [0-21] 2e 70 61 63}  //weight: 1, accuracy: Low
        $x_1_2 = "200.98.162.126/GeraDados.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Banker_Z_2147657408_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.Z"
        threat_id = "2147657408"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dXNlcl9wcmVmKA==" wide //weight: 1
        $x_1_2 = "bmV0d29yay5wcm94eS5hdXRvY29uZmlnX3VybA==" wide //weight: 1
        $x_1_3 = "uok8Y7767yhii7" wide //weight: 1
        $x_1_4 = "taskkill /F /IM firefox.exe & exit" wide //weight: 1
        $x_1_5 = {5c 00 64 00 65 00 6c 00 5f 00 73 00 65 00 6c 00 66 00 2e 00 62 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanProxy_Win32_Banker_AA_2147657573_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.AA"
        threat_id = "2147657573"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "170"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Q7HqS3elBtTtTovYSYrmSczjRsDXRovZRsqkOd8lP6boBsLkO" wide //weight: 100
        $x_50_2 = "JczjPI1aOI1DON5rQMvXBYukBYuw80" wide //weight: 50
        $x_50_3 = "H65qOI1b84XlSc4WBYukBYukBYuw80" wide //weight: 50
        $x_10_4 = "N45ZT6bsPIvYONG" wide //weight: 10
        $x_10_5 = "FJqzFJqzFJqzFJqzFJq" wide //weight: 10
        $x_10_6 = "FlashPlayer.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_10_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Banker_GI_2147658232_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.GI"
        threat_id = "2147658232"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[Delimi]" wide //weight: 1
        $x_1_2 = "\\opera\\opera\\operaprefs.ini" wide //weight: 1
        $x_1_3 = "PHP Read Data" wide //weight: 1
        $x_1_4 = {5c 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 5c 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 5c 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 73 00 5c 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 00 70 00 72 00 65 00 66 00 73 00 2e 00 6a 00 73 00 ?? ?? ?? ?? ?? ?? 5c 00 75 00 73 00 65 00 72 00 2e 00 6a 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Banker_AI_2147658278_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.AI"
        threat_id = "2147658278"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "470"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "empresa.pac" ascii //weight: 100
        $x_100_2 = "karavelacenter@hotmail.com" ascii //weight: 100
        $x_100_3 = "remetente=FTP@hotmail.com" ascii //weight: 100
        $x_50_4 = "querotopsys.com/solucao/email.php" ascii //weight: 50
        $x_50_5 = "prluiz.produtoraalphanet.com.br/lang/email.php" ascii //weight: 50
        $x_30_6 = "jaojeba@hotmail.com" ascii //weight: 30
        $x_30_7 = "recebendo2012@live.com" ascii //weight: 30
        $x_20_8 = "msn10@hotmail.com.br" ascii //weight: 20
        $x_20_9 = "\\ift.txt" ascii //weight: 20
        $x_100_10 = "empresaseikebatista.com/includes/" ascii //weight: 100
        $x_100_11 = "tgklbbnksloop.com/includes/" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_30_*) and 2 of ($x_20_*))) or
            ((3 of ($x_100_*) and 2 of ($x_50_*) and 2 of ($x_30_*) and 1 of ($x_20_*))) or
            ((4 of ($x_100_*) and 1 of ($x_30_*) and 2 of ($x_20_*))) or
            ((4 of ($x_100_*) and 2 of ($x_30_*) and 1 of ($x_20_*))) or
            ((4 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_20_*))) or
            ((4 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_30_*))) or
            ((4 of ($x_100_*) and 2 of ($x_50_*))) or
            ((5 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Banker_AJ_2147658284_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.AJ"
        threat_id = "2147658284"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "270"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {57 5d 43 41 5a 4b 53 19 46 47 56 40 4e 18}  //weight: 100, accuracy: High
        $x_100_2 = "novo.baixevideos-seguro.com/contact" ascii //weight: 100
        $x_50_3 = "r/total_visitas.php" ascii //weight: 50
        $x_20_4 = "jWQBBXJRjxP[EYFV^CjbPV" ascii //weight: 20
        $x_20_5 = {78 4d 43 59 76 56 56 51 5f 52 6c 6a 7b 00}  //weight: 20, accuracy: High
        $x_20_6 = {4b 4c 52 44 6a 49 4a 52 50 1d 1b 56 52 42 42 56 4a 5c 45 18 4b}  //weight: 20, accuracy: High
        $x_20_7 = {41 40 56 52 42 1c 59 47}  //weight: 20, accuracy: High
        $x_40_8 = "contador/log.php" ascii //weight: 40
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_40_*) and 4 of ($x_20_*))) or
            ((2 of ($x_100_*) and 4 of ($x_20_*))) or
            ((2 of ($x_100_*) and 1 of ($x_40_*) and 2 of ($x_20_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_20_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_40_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Banker_AL_2147658456_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.AL"
        threat_id = "2147658456"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 70 61 63 [0-15] 41 75 74 6f 43 6f 6e 66 69 67 55 52 4c}  //weight: 1, accuracy: Low
        $x_1_2 = "destinatario=" ascii //weight: 1
        $x_1_3 = "assunto=Infect" ascii //weight: 1
        $x_1_4 = "remetente=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Banker_AM_2147659343_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.AM"
        threat_id = "2147659343"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "barbarazzifotos.com/new/red.html" wide //weight: 20
        $x_5_2 = {43 6f 6e 6e 65 63 74 69 6f 6e 73 54 61 62 00 00 ff}  //weight: 5, accuracy: High
        $x_1_3 = "planetawebnoticias.com/maps/seg.pac" ascii //weight: 1
        $x_1_4 = "solucoesfat.com/get/pos.pac" ascii //weight: 1
        $x_1_5 = "transpara2012.com/golf/feliz.pac" ascii //weight: 1
        $x_1_6 = "luzanjo.com/mes/pit.pac" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Banker_AN_2147659631_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.AN"
        threat_id = "2147659631"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"esco\", \"bb\", \"h\", \"sbc\"" ascii //weight: 1
        $x_1_2 = "\"edi\", \"ca\", \"rd\", \"inf\"" ascii //weight: 1
        $x_1_3 = "urlsToProxy" ascii //weight: 1
        $x_1_4 = "FindProxyForURL(url, host)" ascii //weight: 1
        $x_1_5 = "WinNTService.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Banker_AP_2147661434_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.AP"
        threat_id = "2147661434"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "112"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\drivers\\etc\\hosts" wide //weight: 1
        $x_1_2 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_3 = "attrib -r" wide //weight: 1
        $x_1_4 = "attrib -r" ascii //weight: 1
        $x_100_5 = "crear_bat" ascii //weight: 100
        $x_10_6 = {76 69 61 62 63 70 2e 63 6f 6d 0d 0a}  //weight: 10, accuracy: High
        $x_10_7 = {69 6e 74 65 72 62 61 6e 6b 2e 63 6f 6d 2e 70 65 0d 0a}  //weight: 10, accuracy: High
        $x_10_8 = {62 6e 2e 63 6f 6d 2e 70 65 0d 0a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Banker_AU_2147666753_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.AU"
        threat_id = "2147666753"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 c7 04 24 80 00 00 00 54 8d 44 24 08 50 e8 ?? ?? ?? ?? 85 c0 74 10 8b c3 8d 54 24 04 b9 80 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c [0-16] 2e 74 78 74 [0-16] 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? 6f 66 66 6c 69 6e 65}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 6f 63 2e [0-32] 2f 2f 3a 70 74 74 68 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 75 74 6f 43 6f 6e 66 69 67 55 52 4c}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? 43 6f 6e 6e 65 63 74 69 6f 6e 73 54 61 62}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 5a 6f 6e 65 4d 61 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 75 74 6f 44 65 74 65 63 74 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 64 76 61 6e 63 65 64}  //weight: 1, accuracy: Low
        $x_1_7 = "mensagem=" ascii //weight: 1
        $x_1_8 = "remetente=" ascii //weight: 1
        $x_1_9 = "destinatario=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanProxy_Win32_Banker_AV_2147669991_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.AV"
        threat_id = "2147669991"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d0 83 e2 03 8a 92 ?? ?? 40 00 30 14 38 40 83 f8 11 7c ec ba fd ff ff ff 2b d1}  //weight: 10, accuracy: Low
        $x_10_2 = {80 36 3b 8b 7d f8 b1 15 30 4e 01 b0 cf 30 46 02 b2 97 30 56 03 30 53 03 30 4b 01 30 4b 05 30 43 02 30 43 06 80 33 3b}  //weight: 10, accuracy: High
        $x_10_3 = {83 e3 03 0f b6 9b ?? ?? 40 00 30 58 02 0f b6 09 30 48 03 0f b6 0f 30 48 04 83 c0 06 8d 0c 02 83 f9 12 7c 8a}  //weight: 10, accuracy: Low
        $x_1_4 = {5a 71 ab b7 19 5d 84 d4 6e 49 9c f8 5d 61 b8 f6}  //weight: 1, accuracy: High
        $x_1_5 = {19 7d bb e3 4b 2f e0 b8 0a 22 f8 b9 03 20 e1 ae 0d 3b fe a6 14 65 ae f4 15 65 a7 e7 19}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Banker_AW_2147678595_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.AW"
        threat_id = "2147678595"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 43 4f 50 41 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 3a 5c 41 64 64 6f 62 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 61 64 64 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {49 4f 4e 5c 52 55 4e 00 00 00 ff ff ff ff 0b 00 00 00 41 6c 74 65 72 6e 61 74 69 76 6f}  //weight: 1, accuracy: High
        $x_1_5 = {ff ba 02 00 00 80 8b c3 e8 ?? ?? ?? ff 33 c9 ba ?? ?? 50 00 8b c3 e8 ?? ?? ?? ff 8b 4d fc ba ?? ?? 50 00 8b c3 e8}  //weight: 1, accuracy: Low
        $x_1_6 = {84 c0 74 16 a1 ?? ?? 50 00 8b 80 44 03 00 00 66 be eb ff e8 ?? ?? ?? ff eb 1d 6a 00 6a 00 6a 00 68 ?? ?? 50 00 68 ?? ?? 50 00 8b c3 e8 ?? ?? ?? ff 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanProxy_Win32_Banker_BA_2147681595_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.BA"
        threat_id = "2147681595"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {69 6e 74 65 72 6e 65 74 2d 6f 70 74 69 6f 6e 73 2e 63 6f 6d 2e 62 72 2f 69 65 [0-16] 41 75 74 6f 43 6f 6e 66 69 67 55 52 4c}  //weight: 10, accuracy: Low
        $x_1_2 = "\\A87AS3HIU4.txt" ascii //weight: 1
        $x_1_3 = "216.245.199.195/index.php" ascii //weight: 1
        $x_1_4 = "\\HAUEHEFUHFUEAN.txt" ascii //weight: 1
        $x_1_5 = "http://sishab.uhosti.com/index.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Banker_BB_2147682444_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.BB"
        threat_id = "2147682444"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TKell_Marques" ascii //weight: 1
        $x_1_2 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 43 3a 5c 46 6f 74 6f 36 32 35 33 34 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {74 69 70 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 74 69 70 6f 3d 69 6e 66}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 70 72 65 66 73 2e 6a 73}  //weight: 1, accuracy: Low
        $x_1_5 = "user_pref(\"network.proxy.autoconfig_url\",\"http://www." ascii //weight: 1
        $x_1_6 = "user_pref(\"network.proxy.type\", 2);" ascii //weight: 1
        $x_1_7 = {41 75 74 6f 43 6f 6e 66 69 67 55 52 4c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 30 78 30 30 30 30 30 30 30 30 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Banker_BD_2147683078_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.BD"
        threat_id = "2147683078"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 65 6d 65 74 65 6e 74 65 3d 70 63 77 40 70 63 77 2e 63 6f 6d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 65 73 74 69 6e 61 74 61 72 69 6f 3d 00}  //weight: 1, accuracy: Low
        $x_1_2 = {63 68 72 6f 6d 65 2e 65 78 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 69 72 65 66 6f 78 2e 65 78 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? 69 65 78 70 6c 6f 72 65 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 75 74 6f 43 6f 6e 66 69 67 55 52 4c}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 5a 6f 6e 65 4d 61 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 75 74 6f 44 65 74 65 63 74 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 64 76 61 6e 63 65 64}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 70 61 63 00 [0-3] ff ff ff ff 3b 00 00 00 53 6f 66 74 77 61 72 65 5c 50 6f 6c 69 63 69 65 73 5c}  //weight: 1, accuracy: Low
        $x_1_6 = {50 72 6f 6a 65 63 74 33 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00}  //weight: 1, accuracy: High
        $x_2_7 = {66 69 72 65 66 6f 78 2e 65 78 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 68 72 6f 6d 65 2e 65 78 65 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Banker_BM_2147688651_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.BM"
        threat_id = "2147688651"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "r_pref(\"network.proxy.autoconfig_url\"," ascii //weight: 2
        $x_2_2 = {73 61 6e 6f 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 75 73 65 72 6e 61 6d 65 70 61 73 73 77 6f 72 64 07 69 64 73 6f 63 6b 73}  //weight: 2, accuracy: High
        $x_1_3 = ".com.br" ascii //weight: 1
        $x_2_4 = "?nomepc=" ascii //weight: 2
        $x_2_5 = ";picas++)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Banker_BN_2147693432_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Banker.BN"
        threat_id = "2147693432"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DisableTaskMgr" ascii //weight: 1
        $x_1_2 = {41 75 74 6f 43 6f 6e 66 69 67 55 52 4c 22 3d 22 68 74 74 70 3a 2f 2f [0-6] 2e [0-6] 2e [0-6] 2e [0-6] 2f 70 72 6f 78 79 70 61 63}  //weight: 1, accuracy: Low
        $x_1_3 = "del /q /s /f \"%DataDir%\"" ascii //weight: 1
        $x_1_4 = "regedit /s C:\\Comando.Reg" ascii //weight: 1
        $x_1_5 = {73 74 61 72 74 20 2f 6d 69 6e 20 43 3a 5c [0-8] 2e 62 61 74}  //weight: 1, accuracy: Low
        $x_1_6 = "enviadedemail.tmp" ascii //weight: 1
        $x_1_7 = "/imagens/erro/index.php" ascii //weight: 1
        $x_1_8 = "\\Proxy.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

