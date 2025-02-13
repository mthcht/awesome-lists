rule PWS_Win32_Payazol_A_2147646909_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Payazol.A"
        threat_id = "2147646909"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Payazol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "passport.the9.com/index/login" ascii //weight: 2
        $x_2_2 = "pay.ips.com.cn" ascii //weight: 2
        $x_2_3 = "upay.10010.com/web/Buycard" wide //weight: 2
        $x_2_4 = "cashier.alipay.com" wide //weight: 2
        $x_2_5 = "pay.ztgame.com:81" wide //weight: 2
        $x_2_6 = "netpay.cmbchina.com/netpayment" wide //weight: 2
        $x_1_7 = "paymentInfo.bankSelect=" ascii //weight: 1
        $x_1_8 = "ebankDeposit.htm" wide //weight: 1
        $x_4_9 = "i=0;for(i=0;i<document.images.length;i++){if(document.images[i]" ascii //weight: 4
        $x_8_10 = {8b 08 ff 51 68 a1 ?? ?? 49 00 8b 00 8b 80 14 03 00 00 8b 80 20 02 00 00 8b 55 fc 8b 08 ff 51 38 a1}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 5 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Payazol_B_2147648090_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Payazol.B"
        threat_id = "2147648090"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Payazol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "pwd.getRsaPasswd2(seed);" ascii //weight: 4
        $x_4_2 = "$(\"pay-memo\").value" ascii //weight: 4
        $x_4_3 = "paySubmit();" ascii //weight: 4
        $x_2_4 = "//pay.paipai.com" wide //weight: 2
        $x_2_5 = "trade_refund/entryagree?deal_id=" wide //weight: 2
        $x_2_6 = "/promote/mall.shtml" ascii //weight: 2
        $x_2_7 = "/trust/plan" ascii //weight: 2
        $x_2_8 = "/pay/index.html" ascii //weight: 2
        $x_2_9 = "//service.paipai.com" wide //weight: 2
        $x_2_10 = "include/gdca.html" ascii //weight: 2
        $x_2_11 = "deal_detail/view?deal_id" wide //weight: 2
        $x_2_12 = "mark_stockout/entry?deal_id=" wide //weight: 2
        $x_2_13 = "tenpay/Jump2tenpay" wide //weight: 2
        $x_2_14 = "static.paipaiimg.com/module" wide //weight: 2
        $x_1_15 = "/post/post.asp" wide //weight: 1
        $x_1_16 = "http://pojiezhuanjia.co.cc" ascii //weight: 1
        $x_1_17 = "pay_money_show.cgi" wide //weight: 1
        $x_1_18 = "pay_step.css" wide //weight: 1
        $x_1_19 = "pay_tips_win.css" wide //weight: 1
        $x_1_20 = "service.qq.com/category/paipai.html" ascii //weight: 1
        $x_1_21 = "pageId=20060&domainId=1&linkId=10&url=" wide //weight: 1
        $x_1_22 = "counter.sina.com.cn/ip" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 9 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 10 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 11 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 7 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_4_*) and 8 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_4_*) and 9 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 10 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 11 of ($x_2_*))) or
            ((3 of ($x_4_*) and 5 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_4_*) and 6 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_4_*) and 7 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_4_*) and 8 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*) and 9 of ($x_2_*))) or
            (all of ($x*))
        )
}

