rule Trojan_Win32_Multsarch_K_2147681181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Multsarch.K"
        threat_id = "2147681181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Multsarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "FastMM Borland Edition" ascii //weight: 10
        $x_10_2 = "WinRAR 201" ascii //weight: 10
        $x_1_3 = "://smshelp.me/?a=rates&" ascii //weight: 1
        $x_1_4 = "archive.exe" ascii //weight: 1
        $x_1_5 = {73 74 69 6d 75 [0-2] 6c 70 72 6f 66 [0-2] 69 74 2e 63 6f 6d 2f}  //weight: 1, accuracy: Low
        $x_1_6 = "://sms91" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Multsarch_Q_2147681182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Multsarch.Q"
        threat_id = "2147681182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Multsarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 50 ff b3 f4 00 00 00 ff b3 f0 00 00 00 51 8b d3 8b 8b cc 00 00 00 8b 43 5c ff 53 58}  //weight: 1, accuracy: High
        $x_1_2 = "soft_search.php?code=" wide //weight: 1
        $x_1_3 = "Cell, ActiV, Beeline, NEO, Dalacom, Pathword. " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Multsarch_T_2147681183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Multsarch.T"
        threat_id = "2147681183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Multsarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "stimulprofit.com" ascii //weight: 5
        $x_2_2 = "/sms-api/" ascii //weight: 2
        $x_1_3 = "/sms_from_soft.php?user_phone=" ascii //weight: 1
        $x_1_4 = "/soft_tinfo.php?code=" ascii //weight: 1
        $x_1_5 = "/payed_queries.php?query=" ascii //weight: 1
        $x_1_6 = "&torrent_id=" ascii //weight: 1
        $x_1_7 = "&platnik_id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Multsarch_U_2147681184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Multsarch.U"
        threat_id = "2147681184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Multsarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 74 74 70 3a 2f 2f 67 77 2e 6e 65 74 6c 69 6e 6b 69 6e 76 65 73 74 2e 63 6f 6d 2f 63 68 65 63 6b 63 6f 64 65 2e 70 68 70 3f 67 77 3d [0-2] 26 64 6f 63 75 6d 65 6e 74 3d [0-32] 26 63 6f 75 6e 74 72 79 3d 65 73 26 63 6f 64 65 3d}  //weight: 10, accuracy: Low
        $x_10_2 = "download_quiet" ascii //weight: 10
        $x_1_3 = "Esta a punto de utilizar una descarga premium, su ayuda nos permite garantizar un mejor servicio." ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f 65 6c 70 61 72 74 69 64 6f 2e 73 6f 66 74 32 30 31 32 2e 6e 65 74 2f 65 73 2f 63 6f 6e 66 69 67 5f [0-4] 2e 78 6d 6c}  //weight: 1, accuracy: Low
        $x_1_5 = "Flash Player 10.0.32.18 (Non-IE)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Multsarch_V_2147681185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Multsarch.V"
        threat_id = "2147681185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Multsarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 3f 61 3d 72 61 74 65 73 26 6e 75 6d 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 c7 43 10 0c 00 33 d2 8d 45 f0 89 55 fc ba ?? ?? ?? ?? ff 43 1c 66 c7 43 10 18 00 66 c7 43 10 24 00 e8 ?? ?? ?? ?? ff 43 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Multsarch_W_2147681186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Multsarch.W"
        threat_id = "2147681186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Multsarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 4d 5a 50 00 02 00 00 00 04 00 0f 00 ff ff 00 00 b8 00 a0 00 07 40 00 1a 00 00 00 fb 10 6a 72}  //weight: 1, accuracy: High
        $x_1_2 = {83 c0 20 0f b7 c0 83 c6 02 66 3b c2 75 0f b7 46 fe 8d 50 be 66 83 fa 17 77 03 83 c0 20 0f b7 c8 0f b7 07 8d 50 be 66 83 fa 17 77 03 83 c0 20 0f b7 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Multsarch_R_2147681187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Multsarch.R"
        threat_id = "2147681187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Multsarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 66 32 2e 76 62 73 00 fe 25 25 5c 77 73 63 72 69 70 74 2e 65 78 65 20 fd 99 80 5c 66 66 32 2e 76 62 73}  //weight: 1, accuracy: High
        $x_1_2 = {66 69 72 65 66 6f 78 32 2e 76 62 73 00 fe 25 25 5c 77 73 63 72 69 70 74 2e 65 78 65 20 fd 99 80 5c 66 69 72 65 66 6f 78 32 2e 76 62 73}  //weight: 1, accuracy: High
        $x_10_3 = {50 6f 75 72 20 6f 62 74 65 6e 69 72 20 76 6f 74 72 65 20 63 6f 64 65 20 64 27 61 63 74 69 76 61 74 69 6f 6e 2c 20 76 65 75 69 6c 6c 65 7a 20 65 6e 76 6f 79 65 72 20 64 65 70 75 69 73 20 76 6f 74 72 65 20 70 6f 72 74 61 62 6c 65 20 75 6e 20 53 4d 53 20 61 75 20 6e 75 6d 65 72 6f 20 [0-5] 20 61 76 65 63 20 6c 65 20 6d 6f 74}  //weight: 10, accuracy: Low
        $x_10_4 = {41 56 45 52 54 49 53 53 45 4d 45 4e 54 20 3a 20 4c 27 41 43 43 c8 53 20 41 55 20 53 45 52 56 49 43 45 20 50 52 45 4d 49 55 4d 20 4e c9 43 45 53 53 49 54 45 52 41 20 4c 27 45 4e 56 4f 49 20 44 45 20 [0-16] 20 53 4d 53 20 50 41 52 20 54 c9 4c c9 43 48 41 52 47 45 4d 45 4e 54 2e}  //weight: 10, accuracy: Low
        $x_10_5 = {53 69 20 76 6f 75 73 20 6e 27 ea 74 65 73 20 70 61 73 20 64 27 61 63 63 6f 72 64 20 61 76 65 63 20 63 65 6c 6c 65 73 2d 63 69 2c 20 76 65 75 69 6c 6c 65 7a 20 6e 65 20 70 61 73 20 61 63 63 e9 64 65 72 20 61 75 78 20 53 65 72 76 69 63 65 73 20 50 72 65 6d 69 75 6d 20 64 65 20 [0-32] 20 65 74 20 66 65 72 6d 65 7a 20 69 6d 6d e9 64 69 61 74 65 6d 65 6e 74 20 63 65 74 74 65 20 70 61 67 65 2c}  //weight: 10, accuracy: Low
        $x_10_6 = {63 3f 67 77 3d [0-3] 26 64 6f 63 75 6d 65 6e 74 3d [0-32] 26 63 6f 75 6e 74 72 79 3d [0-3] 26 63 6f 64 65 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Multsarch_S_2147681188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Multsarch.S"
        threat_id = "2147681188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Multsarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ext.stimulprofit.com/soft_exec.php" wide //weight: 1
        $x_1_2 = "a=rates&num=" wide //weight: 1
        $x_1_3 = "help@zerogravity.kz" wide //weight: 1
        $x_1_4 = "Zero Gravity" wide //weight: 1
        $x_1_5 = "###TORRENT2EXE###" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Multsarch_M_2147681189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Multsarch.M"
        threat_id = "2147681189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Multsarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "tcrypt_cl2\\tcrypt_cl2\\Release\\s_high.pdb" ascii //weight: 20
        $x_20_2 = "tcrypt_cl2\\tcrypt_cl2\\Release\\s_low.pdb" ascii //weight: 20
        $x_20_3 = "\\tcrypt\\Release\\s_high.pdb" ascii //weight: 20
        $x_20_4 = "\\tcrypt\\Release\\s_low.pdb" ascii //weight: 20
        $x_1_5 = {ba 20 37 ef c6 89 74 24 0c bf 20 00 00 00 8b f1 c1 ee 05 03 74 24 0c 8b d9 c1 e3 04}  //weight: 1, accuracy: High
        $x_1_6 = {2b ce 81 c2 47 86 c8 61 83 ef 01 75 bf}  //weight: 1, accuracy: High
        $x_1_7 = {0f b7 11 c1 ea 02 2b fa 83 c1 02 3b f8 74 6e 81 ef 00 40 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {c1 ee 02 8b f8 2b fe 03 d2 2b fa 0f b6 97 ff f7 ff ff 81 ef 01 08 00 00 88 10 40}  //weight: 1, accuracy: High
        $x_1_9 = {6e 1c ff 0d 6f 1e ff 0d 6f 1e ff 0d 6f 1e ff 0d 70 1e ff 0d 71 1c ff 0c 74 19 ff 0c 79 13 ff 02}  //weight: 1, accuracy: High
        $x_1_10 = {37 37 27 23 1d 13 24 39 6e 6f 70 71 72 72 72 72 72 72 73 74 5e 67 75 5e 24 75 68 65 74 72 72 72 72 72}  //weight: 1, accuracy: High
        $x_1_11 = {62 68 61 24 55 5b 53 ea 3a 39 43 ff 32 28 45 ff 3e 31 53 ff 40 32 50 ff 44 2f 4c ff 31 3d 52 ff 20 53 5f ff}  //weight: 1, accuracy: High
        $x_1_12 = {00 24 37 46 37 27 23 1d 24 6f 73 77 73 78 73 73 73 73 73 73 73 74 5e 79 7a 66 66 7a 68 65 74 73 73 73 73 73 73 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Multsarch_N_2147681190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Multsarch.N"
        threat_id = "2147681190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Multsarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "102"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {37 37 27 23 1d 13 24 39 6e 6f 70 71 72 72 72 72 72 72 73 74 5e 67 75 5e 24 75 68 65 74 72 72 72 72 72}  //weight: 100, accuracy: High
        $x_1_2 = "torrent_timer" ascii //weight: 1
        $x_1_3 = "pay_sms" ascii //weight: 1
        $x_1_4 = "sms_num" ascii //weight: 1
        $x_1_5 = "step_text23" ascii //weight: 1
        $x_1_6 = {75 c9 1c cd 5b 4e 72 0e 48 c3 53 de 5a 95 31 df ce 70 1f 5a d6 26 c9 bd c0 f0 e9 55 ac a7 98 bc 94 df bc f4 96 6f c9 65 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Multsarch_O_2147681191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Multsarch.O"
        threat_id = "2147681191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Multsarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "102"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {37 37 27 23 1d 13 24 39 6e 6f 70 71 72 72 72 72 72 72 73 74 5e 67 75 5e 24 75 68 65 74 72 72 72 72 72}  //weight: 100, accuracy: High
        $x_1_2 = "sms_from_soft.php" ascii //weight: 1
        $x_1_3 = "1on_sms911_clicked" ascii //weight: 1
        $x_1_4 = "zak-host.com/fun" ascii //weight: 1
        $x_1_5 = "Gsms_text_num.png" wide //weight: 1
        $x_1_6 = "stimulprofit.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Multsarch_P_2147681192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Multsarch.P"
        threat_id = "2147681192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Multsarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sms911.ru/tarifs.php\" targ" ascii //weight: 1
        $x_1_2 = "input id=\"smscode_psevdo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Multsarch_L_2147681193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Multsarch.L"
        threat_id = "2147681193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Multsarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 81 c2 05 f4 ff ff 83 c2 03 83 ea f9 52 68 83 d0 91 00 50 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

