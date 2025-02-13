rule TrojanSpy_Win32_Alipay_2147646015_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Alipay"
        threat_id = "2147646015"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Alipay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "act=money&username=%s&bank=%s&money=%s&mac=%s&browser=%s&paymode=%d" ascii //weight: 10
        $x_10_2 = "var btn=document.getElementById(\"J-deposit-submit\");btn.onclick=new Function(\"document.getElementById(\\\"ebankDepositForm\\\").submit();return false;\");" ascii //weight: 10
        $x_10_3 = "http://Login_AliPayPassword/" ascii //weight: 10
        $x_5_4 = "TPL_password" wide //weight: 5
        $x_5_5 = "txt_payPassword" wide //weight: 5
        $x_1_6 = "btn_to_ebankPayForm" ascii //weight: 1
        $x_1_7 = "http://click_to_ebankPay/" ascii //weight: 1
        $x_1_8 = "http://www.99bill.com/bankgateway/bankCardPayRedirectResponse.htm" ascii //weight: 1
        $x_1_9 = {68 74 74 70 73 3a 2f 2f 63 61 73 68 69 65 72 2e 61 6c 69 70 61 79 2e 63 6f 6d 2f [0-235] 61 6e 6b}  //weight: 1, accuracy: Low
        $x_1_10 = "https://ebank.bankofbeijing.com.cn/servlet/" ascii //weight: 1
        $x_1_11 = "https://ebank.bjrcb.com/ent/Payment" ascii //weight: 1
        $x_1_12 = "https://ebank.cmbc.com.cn/weblogic/servlets/EService/CSM/NonSignPayPre" ascii //weight: 1
        $x_1_13 = "https://ebank.fudian-bank.com/netpay/Alipay" ascii //weight: 1
        $x_1_14 = "https://ebank.gdb.com.cn/payment/ent_payment.jsp" ascii //weight: 1
        $x_1_15 = "https://ebank.hzbank.com.cn:80/hzpayment/hzbankPay.srv" ascii //weight: 1
        $x_1_16 = "https://ebank.sdb.com.cn/perbank/merpayb" ascii //weight: 1
        $x_1_17 = "https://ebank.spdb.com.cn/payment/main" ascii //weight: 1
        $x_1_18 = "https://epay.bankofshanghai.com/boscartoon/netpay.do" ascii //weight: 1
        $x_1_19 = "https://mybank.nbcb.com.cn/payment/merpayb" ascii //weight: 1
        $x_1_20 = "https://netpay.pingan.com.cn/peps/paBankNetpay.do" ascii //weight: 1
        $x_1_21 = "https://pbank.95559.com.cn/netpay/MerPayB2C" ascii //weight: 1
        $x_1_22 = "https://pbank.psbc.com/pweb/PayGateindex.do" ascii //weight: 1
        $x_1_23 = "https://www.cebbank.com/per/preEpayLogin.do" ascii //weight: 1
        $x_1_24 = {69 63 6f 6e 20 [0-3] 42 41 4e 4b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 15 of ($x_1_*))) or
            (all of ($x*))
        )
}

