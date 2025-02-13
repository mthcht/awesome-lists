rule Trojan_Win32_Ninunarch_B_2147681215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ninunarch.B"
        threat_id = "2147681215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninunarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {24 00 00 00 57 00 69 00 6e 00 5a 00 69 00 70 00 2b 00 3a 00 20 00}  //weight: 1, accuracy: High
        $x_1_2 = "PayArchive" ascii //weight: 1
        $x_1_3 = "http://zipfilez.ru/payarch/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ninunarch_G_2147681238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ninunarch.G"
        threat_id = "2147681238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninunarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sms911.ru" ascii //weight: 10
        $x_10_2 = "winrar.ico" wide //weight: 10
        $x_1_3 = "support.php" ascii //weight: 1
        $x_1_4 = "flexibill.ru/price" ascii //weight: 1
        $x_1_5 = "sms911_clicked()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ninunarch_N_2147681239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ninunarch.N"
        threat_id = "2147681239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninunarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "PAYARCHIVE" ascii //weight: 10
        $x_1_2 = "smsaddinfo>" ascii //weight: 1
        $x_1_3 = "smslist>" ascii //weight: 1
        $x_1_4 = "sms_code>" ascii //weight: 1
        $x_1_5 = "sms_num>" ascii //weight: 1
        $x_1_6 = "sms_cost>" ascii //weight: 1
        $x_1_7 = "region>" ascii //weight: 1
        $x_1_8 = "country>" ascii //weight: 1
        $x_1_9 = "wid>" ascii //weight: 1
        $x_1_10 = "fileid>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ninunarch_O_2147681241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ninunarch.O"
        threat_id = "2147681241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninunarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {12 04 32 04 35 04 34 04 51 04 3d 04 20 00 3d 04 35 04 3f 04 40 04 30 04 32 04 38 04 3b 04 4c 04 3d 04 4b 04 39 04 20 00 3a 04 3e 04 34 04 21 00}  //weight: 1, accuracy: High
        $x_1_2 = {1a 04 3e 04 34 04 20 00 32 04 32 04 35 04 34 04 51 04 3d 04 20 00 32 04 35 04 40 04 3d 04 3e 04 21 00}  //weight: 1, accuracy: High
        $x_1_3 = "Rapidshare-Vip.Net" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ninunarch_R_2147681242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ninunarch.R"
        threat_id = "2147681242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninunarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 89 4d ec 8d 45 ec 50 ff 46 1c e8 ?? ?? ?? ?? ba ?? ?? ?? ?? ff d2 8d 55 ec a1 ?? ?? ?? ?? 83 c4 08 8b 00 8b 12 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {89 3b 8b 08 ff 51 6c 8b fe 89 7d f4 85 ff 74 1e 8b 07 89 45 f8 66 c7 45 e0 2c 00 ba 03 00 00 00 8b 45 f4 8b 08 ff 51 fc 66 c7 45 e0 20 00 8b 55 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ninunarch_S_2147681243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ninunarch.S"
        threat_id = "2147681243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninunarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 6d 00 73 00 39 00 31 00 31 00 2e 00 72 00 75 00 2f 00 74 00 61 00 72 00 69 00 66 00 73 00 2e 00 70 00 68 00 70 00 3f 00 63 00 6f 00 75 00 6e 00 74 00 72 00 79 00 5f 00 69 00 64 00 3d 00 [0-6] 26 00 6e 00 75 00 6d 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "winrar-update/?guid=%GUID%&os=%OS" wide //weight: 1
        $x_1_3 = "07F7E5F0-7E2E-495a-B28A-B5E5E52559C2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ninunarch_H_2147681244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ninunarch.H"
        threat_id = "2147681244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninunarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ":/pic/winrar_small.ico" ascii //weight: 2
        $x_2_2 = "8109580" ascii //weight: 2
        $x_3_3 = "on_editAnswerCodeSecond_textChanged(QString)" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ninunarch_I_2147681245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ninunarch.I"
        threat_id = "2147681245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninunarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {3f 04 35 04 48 04 3d 04 3e 04 20 00 43 04 34 04 30 04 3b 04 51 04 3d 04 4b 04 21 00 0a 00 1d 04}  //weight: 4, accuracy: High
        $x_3_2 = "btn_unrar" ascii //weight: 3
        $x_4_3 = "!key=%KEYPATH%\\key [xnum]%XNUM%[/xnum][xid]%XID%[/xid]" wide //weight: 4
        $x_4_4 = "href = \"http://sms911.ru/tarifs.php" ascii //weight: 4
        $x_4_5 = {73 6d 73 74 65 78 74 3d 22 [0-5] 22 20 73 6d 73 6e 75 6d 3d 22}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ninunarch_T_2147681246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ninunarch.T"
        threat_id = "2147681246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninunarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "check-updates/?guid=%GUID%&parid=%PARID%&xnum=%XNUM%&xid=%XID" wide //weight: 1
        $x_1_2 = "Software\\vamzipper" wide //weight: 1
        $x_1_3 = "prevedhacker" wide //weight: 1
        $x_1_4 = "7E0F3F10-7B69-8C21" wide //weight: 1
        $x_1_5 = "autostar_1917" wide //weight: 1
        $x_1_6 = "&nomer=undefined_in_sms_mode&param=%PARAM%" wide //weight: 1
        $x_1_7 = "archive-sx.net/pass_check" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Ninunarch_K_2147681247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ninunarch.K"
        threat_id = "2147681247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninunarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {37 37 27 23 1d 13 24 39 6e 6f 70 71 72 72 72 72 72 72 73 74 5e 67 75 5e 24 75 68 65 74 72 72 72 72 72}  //weight: 100, accuracy: High
        $x_10_2 = "d1o2o3h4k5t6t7m8c9u0p1k2i3u4t" ascii //weight: 10
        $x_1_3 = "labelRetrySendSMS" ascii //weight: 1
        $x_1_4 = "QFtpDTP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ninunarch_L_2147681248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ninunarch.L"
        threat_id = "2147681248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninunarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {4b c4 52 ff 46 b8 4c ff 05 0e 05 59 ff ff ff 01 00 01 00 17 52 70 53 cf ac e4 af ff b4 e6 b7 ff bd e9 bf ff c8}  //weight: 100, accuracy: High
        $x_10_2 = "d1o2o3h4k5t6t7m8c9u0p1k2i3u4t" ascii //weight: 10
        $x_1_3 = "labelRetrySendSMS" ascii //weight: 1
        $x_1_4 = "QFtpDTP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ninunarch_M_2147681249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ninunarch.M"
        threat_id = "2147681249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninunarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 61 73 68 4d 61 67 6e 61 74 5c 64 61 74 61 00 49 4e 46 4f}  //weight: 1, accuracy: High
        $x_1_2 = {69 63 6f 2e 64 61 74 00 69 63 6f 2e 69 63 6f 00 46 4c 49 53 54 00 43 4f 56 45 52}  //weight: 1, accuracy: High
        $x_1_3 = "kernel32::CreateMutexA(i 0, i 0, t \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ninunarch_Q_2147681250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ninunarch.Q"
        threat_id = "2147681250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninunarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "/sync/pay/?ajax=1&go=auth&password=%s&crypt=" ascii //weight: 6
        $x_1_2 = "aHR0cDovL2Rvd25sb2Fkc3VwcG9ydC5iaXo=" ascii //weight: 1
        $x_1_3 = "3e4/3e4/do3e4wn3e4lo3e4a3e4ds3e4up3e4po3e4rt3e4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ninunarch_P_2147681251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ninunarch.P"
        threat_id = "2147681251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninunarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fd 9a 80 5c 6f 67 75 72 63 68 65 6e 6e 69 6b 6f 76 35 39 32 38 37 2e 6d 61 72 67 2e 70 75 68 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 6f 6d 61 72 62 61 6e 61 6e 37 38 32 2e 6d 61 72 67 2e 70 75 68 00}  //weight: 1, accuracy: High
        $x_1_3 = {fd 95 80 5c 79 61 6d 75 72 69 6c 6b 69 6e 32 39 38 2d 3e fd 95 80 5c 77 69 6e 7a 69 70 66 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 6f 67 75 72 63 68 65 6e 6e 69 6b 6f 76 35 39 32 38 37 2d 3e fd 95 80 5c 61 2e 68 74 6d 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 6f 66 74 77 61 72 65 5c 77 69 6e 78 67 7a 00}  //weight: 1, accuracy: High
        $x_1_6 = {fd 95 80 5c 62 7a 69 70 66 72 65 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {fd 95 80 5c 7a 69 70 73 6d 61 72 74 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Ninunarch_J_2147681252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ninunarch.J"
        threat_id = "2147681252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninunarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "vpatchfile" ascii //weight: 1
        $x_10_2 = "sms911.ru/tarifs.php?country_id=1&num=2858" ascii //weight: 10
        $x_10_3 = {63 6c 6f 73 65 64 [0-1] 2d 64 65 70 66 69 6c 65 73 2e 63 6f 6d 2f (6d 74 78 75 70 72 2e 70|73 6d 73 2d 75 61 2e 68 74)}  //weight: 10, accuracy: Low
        $x_10_4 = {73 77 69 64 65 72 6d 61 6c 34 2e 6e 6f 72 61 2d 3e fd 95 80 5c 73 77 69 64 65 72 6d 61 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? fd 95 80 5c 61 72 63 68 73 74 61 72 74 2e 65 78 65}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

