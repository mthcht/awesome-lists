rule Trojan_AndroidOS_Fakeapp_A_2147707844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakeapp.A"
        threat_id = "2147707844"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakeapp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sppromo.ru/apps.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakeapp_E_2147830154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakeapp.E!MTB"
        threat_id = "2147830154"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakeapp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/example/mobilpakket" ascii //weight: 1
        $x_1_2 = "wezzx.ru/apkpril?keyword" ascii //weight: 1
        $x_1_3 = "setJavaScriptEnabled" ascii //weight: 1
        $x_1_4 = "loadUrl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakeapp_G_2147833354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakeapp.G!MTB"
        threat_id = "2147833354"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakeapp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "webViewGirls" ascii //weight: 1
        $x_1_2 = "&productSL=" ascii //weight: 1
        $x_1_3 = "api&tracking=" ascii //weight: 1
        $x_1_4 = "webViewTerms" ascii //weight: 1
        $x_1_5 = "app_db=apks_data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakeapp_I_2147833844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakeapp.I!MTB"
        threat_id = "2147833844"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakeapp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "revappgreen.ads.zumotu.xyz" ascii //weight: 1
        $x_1_2 = "new.xyz/?v=ag" ascii //weight: 1
        $x_1_3 = "sms.mysmspanel.xyz" ascii //weight: 1
        $x_1_4 = "getHideAppIcon" ascii //weight: 1
        $x_1_5 = "ZumotuFactory" ascii //weight: 1
        $x_1_6 = "phone.mysmspanel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakeapp_F_2147838368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakeapp.F"
        threat_id = "2147838368"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakeapp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your Victim Recieved SMS from" ascii //weight: 1
        $x_1_2 = "access$getSmsManager$cp" ascii //weight: 1
        $x_1_3 = "Lcyber/pthk/smsforwarder/services/SmsListener" ascii //weight: 1
        $x_1_4 = "pduObjects" ascii //weight: 1
        $x_1_5 = "hack_baack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakeapp_M_2147850582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakeapp.M"
        threat_id = "2147850582"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakeapp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZWpmb2cjJG5HamJvc2JnR2ZvZndmJCNibWcjbmZ3a2xnIyRsbUdmb2Z3ZiQ" ascii //weight: 1
        $x_1_2 = "Zm1ydmZ2ZldsYnB3Rns" ascii //weight: 1
        $x_1_3 = "ZWpmb2cjJG5HamJvc2JnSm1zdnck" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakeapp_M_2147850582_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakeapp.M"
        threat_id = "2147850582"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakeapp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "is not a dangerous permission or special permission" ascii //weight: 1
        $x_1_2 = "systemPhotoLists" ascii //weight: 1
        $x_1_3 = "wresultMapdada" ascii //weight: 1
        $x_1_4 = "the anr process found" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakeapp_AT_2147888997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakeapp.AT"
        threat_id = "2147888997"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakeapp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zzofqhb33" ascii //weight: 1
        $x_1_2 = "wvejrb1" ascii //weight: 1
        $x_1_3 = "zyzbnp15" ascii //weight: 1
        $x_1_4 = "webview_windxila_love" ascii //weight: 1
        $x_1_5 = "web_windxila_up" ascii //weight: 1
        $x_1_6 = "webAaxthlingProgress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_Fakeapp_TR_2147890032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakeapp.TR"
        threat_id = "2147890032"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakeapp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mailto:help@multimine.info" ascii //weight: 1
        $x_1_2 = "ETH Mining is Currently Running. Please Stop After you can Withdraw Satoshi" ascii //weight: 1
        $x_1_3 = "millisLeftBCH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakeapp_RE_2147890502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakeapp.RE"
        threat_id = "2147890502"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakeapp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ef70fc48cd9bbe39e74e1fc74596552b" ascii //weight: 1
        $x_1_2 = "cryptominer.bitcoinminer.ui.history" ascii //weight: 1
        $x_1_3 = "vpnmasterfree.vpnmasterproxy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakeapp_V_2147896289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakeapp.V"
        threat_id = "2147896289"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakeapp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aM9zzvcn/MQsglcDoSnReA==" ascii //weight: 1
        $x_1_2 = "com.apklkwes.dasmwlr8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakeapp_L_2147914273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakeapp.L"
        threat_id = "2147914273"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakeapp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dianping://" ascii //weight: 1
        $x_1_2 = "http://wap.cnanzhi.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakeapp_E_2147915742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakeapp.E"
        threat_id = "2147915742"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakeapp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "47.107.80.243:16779/api/uploadImgs" ascii //weight: 1
        $x_1_2 = "47.107.80.243:16779/api/subSmsList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakeapp_HT_2147927146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakeapp.HT"
        threat_id = "2147927146"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakeapp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "V1hwT1UyVldjRmhTYmxFOQ" ascii //weight: 1
        $x_1_2 = "V2tjeFYyVlhUWGxpU0ZwcFdub3dPUT09" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

