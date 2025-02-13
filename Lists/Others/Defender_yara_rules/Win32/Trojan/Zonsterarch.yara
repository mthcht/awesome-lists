rule Trojan_Win32_Zonsterarch_A_2147680177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonsterarch.A"
        threat_id = "2147680177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2d 44 5a 00 01 0f 84 ?? ?? 00 00 2d 00 00 00 0b 0f 85 ?? ?? 00 00 83 ?? 08 71}  //weight: 2, accuracy: Low
        $x_1_2 = {3c 73 74 72 20 69 64 3d 22 ?? ?? 22 3e 59 6f 75 20 6e 65 65 64 20 74 6f 20 73 65 6e 64 20 25 64 20 53 4d 53}  //weight: 1, accuracy: Low
        $x_1_3 = "credit/?pay=" ascii //weight: 1
        $x_1_4 = "[@cid=\"%s\"]/base[@cost=\"%d\"]/price" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zonsterarch_Q_2147680476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonsterarch.Q"
        threat_id = "2147680476"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://downloadfast.ru/exe/index.php" wide //weight: 1
        $x_1_2 = "Could not find MyDocuments folder location." wide //weight: 1
        $x_1_3 = "Select Folder" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zonsterarch_T_2147680477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonsterarch.T"
        threat_id = "2147680477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2f 00 2f 00 63 00 6f 00 75 00 6e 00 74 00 72 00 79 00 5b 00 40 00 63 00 69 00 64 00 3d 00 22 00 25 00 73 00 22 00 5d 00 [0-10] 2f 00 62 00 61 00 73 00 65 00 5b 00 40 00 63 00 6f 00 73 00 74 00 3d 00 22 00 25 00 73 00 22 00 5d 00 [0-10] 2f 00 70 00 72 00 69 00 63 00 65 00 5b 00 40 00 73 00 75 00 62 00 3d 00}  //weight: 2, accuracy: Low
        $x_1_2 = {70 61 79 66 6f 72 6d 2e 70 68 70 00 [0-10] 68 74 74 70 3a 2f 2f 70 61 79 6d 65 6e 74 2e 00}  //weight: 1, accuracy: Low
        $x_1_3 = {61 72 63 68 69 76 65 3d 00 [0-14] 6e 75 6d 62 65 72 3d 00 [0-14] 70 68 6f 6e 65 3d 00 [0-14] 73 65 6e 64 73 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = "paypal/?pay=" ascii //weight: 1
        $x_1_5 = "alertpay/?pay=" ascii //weight: 1
        $x_1_6 = "RUSSIAN_CHARSET" ascii //weight: 1
        $x_1_7 = "%d SMS-" wide //weight: 1
        $x_1_8 = "alt_pay_base_url" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zonsterarch_AF_2147680478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonsterarch.AF"
        threat_id = "2147680478"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PROD_COOKIE_URL=" ascii //weight: 1
        $x_1_2 = {49 6e 74 65 72 6e 61 6c 41 75 74 6f 50 6f 70 75 70 4d 73 67 00}  //weight: 1, accuracy: High
        $x_1_3 = "CustomerRegWebSiteURL" ascii //weight: 1
        $x_1_4 = "SET_PAYPAGE_URL" ascii //weight: 1
        $x_1_5 = "LOGVARNAMEPAID" ascii //weight: 1
        $x_1_6 = "action={ACTION_ID}&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Zonsterarch_AB_2147680479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonsterarch.AB"
        threat_id = "2147680479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[xnum]%XNUM%[/xnum][xid]%XID%[/xid]" wide //weight: 1
        $x_1_2 = "%DOMAIN%/check-updates/?guid=%GUID%&parid=%PARID%&xnum=%XNUM%&xid=%XID" wide //weight: 1
        $x_1_3 = "Software\\winxarj" wide //weight: 1
        $x_1_4 = "prevedhacker" wide //weight: 1
        $x_1_5 = {73 65 6e 64 6e 75 6d 62 65 72 [0-4] 73 6d 73 76 61 72 31 [0-4] 73 6d 73 76 61 72 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Zonsterarch_AC_2147680480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonsterarch.AC"
        threat_id = "2147680480"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[xid]%XID%[/xid][xnum]%XNUM%[/xnum]" wide //weight: 1
        $x_1_2 = "check-updates/?guid=%GUID%&parid=%PARID%&xnum=%XNUM%&xid=%XID" wide //weight: 1
        $x_1_3 = "Software\\winxgz" wide //weight: 1
        $x_1_4 = "prevedhacker" wide //weight: 1
        $x_1_5 = {73 65 6e 64 6e 75 6d 62 65 72 [0-4] 73 76 31 [0-4] 73 76 32}  //weight: 1, accuracy: Low
        $x_1_6 = "Software\\winsmartzip" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Zonsterarch_P_2147680481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonsterarch.P"
        threat_id = "2147680481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "payment_sms_cost" ascii //weight: 1
        $x_1_2 = "zipconnect.in" ascii //weight: 1
        $x_1_3 = "alt_pay_base_url" ascii //weight: 1
        $x_1_4 = "z_s(\"zm_sms\",true)" wide //weight: 1
        $x_1_5 = "alertpay/?pay=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Zonsterarch_AD_2147680482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonsterarch.AD"
        threat_id = "2147680482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "prevedhacker" wide //weight: 1
        $x_1_2 = {12 04 32 04 35 04 34 04 51 04 3d 04 20 00 3d 04 35 04 3f 04 40 04 30 04 32 04 38 04 3b 04 4c 04 3d 04 4b 04 39 04 20 00 3a 04 3e 04 34 04 21 00}  //weight: 1, accuracy: High
        $x_1_3 = {3f 04 35 04 48 04 3d 04 3e 04 20 00 43 04 34 04 30 04 3b 04 51 04 3d 04 4b 04 21 00 0a 00 1d 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zonsterarch_AG_2147680483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonsterarch.AG"
        threat_id = "2147680483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "verify.smsstatus.com/sms/isvalid2.php" ascii //weight: 4
        $x_4_2 = "shareware.pro/support" ascii //weight: 4
        $x_4_3 = "Toolbar.exe\" /s -silent" ascii //weight: 4
        $x_1_4 = "browser.startup.homepage" ascii //weight: 1
        $x_1_5 = "-DefaultSearch=TRUE" ascii //weight: 1
        $x_1_6 = "RunElevated" ascii //weight: 1
        $x_1_7 = "captura.bmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zonsterarch_U_2147680484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonsterarch.U"
        threat_id = "2147680484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "btnSendSmsClick" ascii //weight: 10
        $x_10_2 = "alt_pay_base_url" ascii //weight: 10
        $x_10_3 = "btnGoWebPaymentClick" ascii //weight: 10
        $x_1_4 = "zipconnect.in" ascii //weight: 1
        $x_1_5 = "zip-help.com" ascii //weight: 1
        $x_1_6 = "zipmonster.ru/main" ascii //weight: 1
        $x_1_7 = "//country[@cid=\"%s\"]/base[@cost=\"%s\"]/price[@sub=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zonsterarch_V_2147680485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonsterarch.V"
        threat_id = "2147680485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {50 4d 5f 53 4d 53 05 50 4d 5f 57 4d 06 50 4d 5f 49 56 52 09 50 4d 5f 50 61 79 50 61 6c 09 50 4d 5f 43 72 65 64 69 74 05 50 4d 5f 56 4b}  //weight: 2, accuracy: High
        $x_2_2 = "//country[@cid=\"%s\"]/base[@cost=\"%s\"]/price[@sub=" ascii //weight: 2
        $x_1_3 = "payment_sms_cost=150" wide //weight: 1
        $x_1_4 = "zipconnect.in</alt_api_base_url>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zonsterarch_W_2147680486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonsterarch.W"
        threat_id = "2147680486"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 7d d8 30 04 00 00 0f 83 ab 01 00 00 8b 55 f4 83 c2 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zonsterarch_X_2147680487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonsterarch.X"
        threat_id = "2147680487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {14 00 00 00 53 65 74 50 72 6f 63 65 73 73 44 45 50}  //weight: 10, accuracy: High
        $x_10_2 = {37 37 27 23 1d 13 24 39 6e 6f 70 71 72 72 72 72 72 72 73 74 5e 67 75 5e 24 75 68 65 74 72 72 72 72 72}  //weight: 10, accuracy: High
        $x_1_3 = {d9 45 ec d8 ?? ?? ?? ?? 00 df e0 9e 77 44 d9 45 ec d8 ?? ?? ?? ?? 00 d9 5d ec d9 45 ec 51 d9 1c 24 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zonsterarch_Y_2147680488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonsterarch.Y"
        threat_id = "2147680488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 d2 89 55 e8 eb 2d 8b 45 e8 f7 d0 89 45 e8 8b 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zonsterarch_Z_2147680489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonsterarch.Z"
        threat_id = "2147680489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 6b 79 70 65 [0-128] 65 6c 33 32 3a 3a 43 72 65 61 74 65 4d 75 74 65 78 41 28 69 20 30 2c}  //weight: 1, accuracy: Low
        $x_1_2 = "::Swil(t r1, t r3) i.s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zonsterarch_AA_2147680490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonsterarch.AA"
        threat_id = "2147680490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "alt_pay_base_url" ascii //weight: 1
        $x_1_2 = "archive.smscount" wide //weight: 1
        $x_1_3 = "\"zm_country\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zonsterarch_AE_2147680491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonsterarch.AE"
        threat_id = "2147680491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "paypal/?pay=" ascii //weight: 1
        $x_1_2 = "alertpay/?pay=" ascii //weight: 1
        $x_1_3 = "_z_st(\"zm_sms_number\",t.sms.number);" wide //weight: 1
        $x_1_4 = "(nc * t.sms.r_price) > (archive.smscount * archive.smscost * _BC) ) --nc;" wide //weight: 1
        $x_1_5 = "_z_ge(\"zm_country\").onchange=_z_cc_c;" wide //weight: 1
        $x_1_6 = "zm_payform" ascii //weight: 1
        $x_1_7 = "RUSSIAN_CHARSET" ascii //weight: 1
        $x_1_8 = "TCellOperators" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zonsterarch_R_2147680492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonsterarch.R"
        threat_id = "2147680492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b d2 44 81 fa 52 02 00 00 76 11 8b 45 f8 69 c0 87 61 01 00 8b 4d f0 03 c8 89 4d f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zonsterarch_S_2147680493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonsterarch.S"
        threat_id = "2147680493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 4d 5f 53 4d 53 05 50 4d 5f 57 4d 06 50 4d 5f 49 56 52 09 50 4d 5f 50 61 79 50 61 6c 09 50 4d 5f 43 72 65 64 69 74 05 50 4d 5f 56 4b}  //weight: 1, accuracy: High
        $x_1_2 = {61 6c 74 5f 62 61 73 65 5f 75 72 6c 00 00 00 00 ff ff ff ff 10 00 00 00 61 6c 74 5f 61 70 69 5f 62 61 73 65 5f 75 72 6c 00 00 00 00 ff ff ff ff 10 00 00 00 61 6c 74 5f 70 61 79 5f 62 61 73 65 5f 75 72 6c}  //weight: 1, accuracy: High
        $x_1_3 = "lblSmsCount" ascii //weight: 1
        $x_1_4 = "%d SMS-" wide //weight: 1
        $x_1_5 = "\\ZipMonster\\Soft\\Sources\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zonsterarch_BW_2147705637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zonsterarch.BW"
        threat_id = "2147705637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "_z_st(\"zm_sms_number\",t.sms.number);" wide //weight: 1
        $x_1_2 = "paypal/?pay=" ascii //weight: 1
        $x_1_3 = {61 72 63 68 69 76 65 3d 00 [0-14] 6e 75 6d 62 65 72 3d 00 [0-14] 70 68 6f 6e 65 3d 00 [0-14] 73 65 6e 64 73 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = {70 61 79 66 6f 72 6d 2e 70 68 70 00 [0-10] 68 74 74 70 3a 2f 2f 70 61 79 6d 65 6e 74 2e 00}  //weight: 1, accuracy: Low
        $x_1_5 = {50 4d 5f 53 4d 53 05 50 4d 5f 57 4d 06 50 4d 5f 49 56 52 09 50 4d 5f 50 61 79 50 61 6c 09 50 4d 5f 43 72 65 64 69 74 05 50 4d 5f 56 4b}  //weight: 1, accuracy: High
        $x_1_6 = {61 6c 74 5f 62 61 73 65 5f 75 72 6c 00 00 00 00 ff ff ff ff 10 00 00 00 61 6c 74 5f 61 70 69 5f 62 61 73 65 5f 75 72 6c 00 00 00 00 ff ff ff ff 10 00 00 00 61 6c 74 5f 70 61 79 5f 62 61 73 65 5f 75 72 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

