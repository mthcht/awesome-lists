rule Trojan_Win32_Socelars_S_2147744171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Socelars.S!MSR"
        threat_id = "2147744171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Socelars"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://www.createinfo.pw/Home/Index/getdata" ascii //weight: 2
        $x_2_2 = "http://www.jsxjbxx.pw" ascii //weight: 2
        $x_1_3 = "BillingTransactionsDataLoader" wide //weight: 1
        $x_1_4 = "payment_method" ascii //weight: 1
        $x_2_5 = "F:\\facebook20190527_newversion\\database\\Release\\DiskScan.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Socelars_PA_2147745751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Socelars.PA!MTB"
        threat_id = "2147745751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Socelars"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yesterday" wide //weight: 1
        $x_1_2 = "mutex detected" ascii //weight: 1
        $x_1_3 = "https://iplogger.org/" ascii //weight: 1
        $x_1_4 = "https://graph.facebook.com/v4.0/act_" ascii //weight: 1
        $x_1_5 = "payment_method_stored_balances" ascii //weight: 1
        $x_1_6 = "Baccount_id" ascii //weight: 1
        $x_1_7 = "credit_card_address" ascii //weight: 1
        $x_1_8 = "current_balance" ascii //weight: 1
        $x_1_9 = "payment_method_paypal" ascii //weight: 1
        $x_1_10 = "https://secure.facebook.com/ads/manager/account_settings/account_billing/" ascii //weight: 1
        $x_1_11 = "select count(*) as RCount from cookies" ascii //weight: 1
        $x_1_12 = "FROM moz_cookies where host='.facebook.com';" ascii //weight: 1
        $x_1_13 = "select * from logins where blacklisted_by_user=0 and preferred=1 and  origin_url like" ascii //weight: 1
        $x_1_14 = "datr|sb|c_user|xs|pl|fr" ascii //weight: 1
        $x_1_15 = "no fbcookies found" ascii //weight: 1
        $x_1_16 = "amazon_us" ascii //weight: 1
        $x_1_17 = "amazon_uk" ascii //weight: 1
        $x_1_18 = "c_user" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

