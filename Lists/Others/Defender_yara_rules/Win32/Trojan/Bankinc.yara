rule Trojan_Win32_Bankinc_A_2147678809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bankinc.A"
        threat_id = "2147678809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bankinc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sinaSSOEncoder.hex_sha1" wide //weight: 1
        $x_1_2 = "/code/postbmp.asp?filename=" wide //weight: 1
        $x_1_3 = "/sfz/getquhao.asp?id=" wide //weight: 1
        $x_1_4 = {2f 00 73 00 6f 00 66 00 74 00 2f 00 63 00 68 00 61 00 6e 00 67 00 79 00 6f 00 75 00 2f 00 69 00 70 00 [0-2] 2e 00 61 00 73 00 70 00}  //weight: 1, accuracy: Low
        $x_1_5 = ":88/soft/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bankinc_B_2147678817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bankinc.B"
        threat_id = "2147678817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bankinc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sinaSSOEncoder.hex_sha1" wide //weight: 1
        $x_1_2 = ".bat&echo del c:\\" wide //weight: 1
        $x_1_3 = {3a 00 38 00 38 00 2f 00 73 00 6f 00 66 00 74 00 2f 00 78 00 69 00 61 00 6f 00 6d 00 69 00 2f 00 70 00 6f 00 73 00 74 00 [0-16] 2e 00 61 00 73 00 70 00 3f 00 69 00 64 00 3d 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {00 41 6e 74 69 56 43 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 68 6f 75 7a 75 69 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bankinc_C_2147678821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bankinc.C"
        threat_id = "2147678821"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bankinc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 00 38 00 38 00 2f 00 73 00 6f 00 66 00 74 00 2f 00 71 00 71 00 2f 00 72 00 65 00 67 00 2f 00 70 00 6f 00 73 00 74 00 [0-16] 2e 00 61 00 73 00 70 00 3f 00 71 00 71 00 3d 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = " 127.1 -n 3 >nul 2>nul >c:\\" wide //weight: 1
        $x_1_3 = "/sfz/getquhao.asp?id=" wide //weight: 1
        $x_1_4 = {2f 00 73 00 6f 00 66 00 74 00 2f 00 63 00 68 00 61 00 6e 00 67 00 79 00 6f 00 75 00 2f 00 67 00 65 00 74 00 [0-16] 2e 00 61 00 73 00 70 00 3f 00 69 00 64 00 3d 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bankinc_2147679612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bankinc"
        threat_id = "2147679612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bankinc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sinaSSOEncoder" wide //weight: 1
        $x_1_2 = "/postbmp.asp" wide //weight: 1
        $x_1_3 = "/getquhao.asp" wide //weight: 1
        $x_1_4 = "/changyou/" wide //weight: 1
        $x_1_5 = ":88/soft/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Bankinc_2147679612_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bankinc"
        threat_id = "2147679612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bankinc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "disabled=\"disabled\"" ascii //weight: 1
        $x_1_2 = "cashier.alipay.com" ascii //weight: 1
        $x_1_3 = "pay.ztgame.com" ascii //weight: 1
        $x_1_4 = "pay.sdo.com" ascii //weight: 1
        $x_1_5 = "payment.chinapay.com" ascii //weight: 1
        $x_1_6 = "www.esaipai.com" ascii //weight: 1
        $x_1_7 = "result.tenpay.com" ascii //weight: 1
        $x_1_8 = "pay.qq.com" ascii //weight: 1
        $x_1_9 = "pay.95559.com.cn" ascii //weight: 1
        $x_1_10 = "netpay.cmbchina.com" ascii //weight: 1
        $x_1_11 = "pbank.psbc.com" ascii //weight: 1
        $x_1_12 = "ebs.boc.cn" ascii //weight: 1
        $x_1_13 = "ibsbjstar.ccb.com.cn" ascii //weight: 1
        $x_1_14 = "epay.163.com" ascii //weight: 1
        $x_1_15 = "pay.4399.com" ascii //weight: 1
        $x_1_16 = "netpay.pingan.com.cn" ascii //weight: 1
        $x_1_17 = "ebank.spdb.com.cn" ascii //weight: 1
        $x_1_18 = "ebanks.cgbchina.com.cn" ascii //weight: 1
        $x_1_19 = "pay.my.xoyo.com" ascii //weight: 1
        $x_1_20 = "pay.renren.com" ascii //weight: 1
        $x_1_21 = "bank.ecitic.com" ascii //weight: 1
        $x_1_22 = "www.99bill.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Bankinc_D_2147681962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bankinc.D"
        threat_id = "2147681962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bankinc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0b 83 c3 04 8b 32 83 c2 04 f3 a4 48 75 f1}  //weight: 1, accuracy: High
        $x_1_2 = "disabled=\"disabled\"" wide //weight: 1
        $x_1_3 = "cashier.alipay.com" ascii //weight: 1
        $x_1_4 = "pay.ztgame.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

