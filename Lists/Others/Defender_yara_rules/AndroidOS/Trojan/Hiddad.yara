rule Trojan_AndroidOS_Hiddad_B_2147763794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hiddad.B!MTB"
        threat_id = "2147763794"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hiddad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/RestartViewAdsServiceReceiver;" ascii //weight: 1
        $x_1_2 = "/GetAdmService;" ascii //weight: 1
        $x_1_3 = "StopViewAdsService" ascii //weight: 1
        $x_1_4 = "count_click" ascii //weight: 1
        $x_1_5 = "/debug/?i=" ascii //weight: 1
        $x_1_6 = "setComponentEnabledSetting" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Hiddad_A_2147783563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hiddad.A"
        threat_id = "2147783563"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hiddad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/RestartViewAdsServiceReceiver;" ascii //weight: 1
        $x_1_2 = "/GetAdmService;" ascii //weight: 1
        $x_1_3 = "ViewAdsActivity" ascii //weight: 1
        $x_1_4 = "StopViewAdsService" ascii //weight: 1
        $x_1_5 = "L3ByZWNlcHQvP2k9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Hiddad_C_2147796988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hiddad.C!MTB"
        threat_id = "2147796988"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hiddad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "onAdLoaded" ascii //weight: 1
        $x_1_2 = "sdk/Injector" ascii //weight: 1
        $x_1_3 = "acalaman.com" ascii //weight: 1
        $x_1_4 = "setAdListener" ascii //weight: 1
        $x_1_5 = "setComponentEnabledSetting" ascii //weight: 1
        $x_1_6 = "com/adcommercial/utils/Triple" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Hiddad_E_2147821102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hiddad.E!MTB"
        threat_id = "2147821102"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hiddad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 46 be f1 00 0f 15 ?? 09 f1 ff 37 01 38 00 23 03 f0 03 01 0d f1 18 0c 61 44 01 33 17 f8 01 2f 73 45 11 f8 08 1c 82 ea 01 02 00 f8 01 2f ef ?? dd f8 0c e0 00 23 08 f8 0e 30 b9 f1 00 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Hiddad_F_2147831444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hiddad.F!MTB"
        threat_id = "2147831444"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hiddad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "am/xtrack/LolaActivity" ascii //weight: 1
        $x_1_2 = ".nconfhz.com" ascii //weight: 1
        $x_1_3 = "INTENT_ACTION_AD_SHOW" ascii //weight: 1
        $x_1_4 = "adLoaded" ascii //weight: 1
        $x_1_5 = "lock_enable_ad" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Hiddad_R_2147847939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hiddad.R"
        threat_id = "2147847939"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hiddad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "classes_dex_digest" ascii //weight: 1
        $x_1_2 = "Is your intent spelled correctly" ascii //weight: 1
        $x_1_3 = "com.aqplay.proxy.impl.ProxyManager" ascii //weight: 1
        $x_1_4 = "G00FxfBObgfgTvzgaAvaluBXTnvu0N2t5KG0ubQC24d2dTrr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_Hiddad_G_2147850536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hiddad.G!MTB"
        threat_id = "2147850536"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hiddad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fileCom/recover/keep" ascii //weight: 1
        $x_1_2 = "AdSessionConfiguration" ascii //weight: 1
        $x_1_3 = "injectScriptContentIntoHtml" ascii //weight: 1
        $x_1_4 = "isOrWillBeHidden" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Hiddad_B_2147889032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hiddad.B"
        threat_id = "2147889032"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hiddad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/vid007/videobuddy" ascii //weight: 1
        $x_1_2 = "need show reward ad" ascii //weight: 1
        $x_1_3 = "sisyphus/lockscreens" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Hiddad_H_2147923946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hiddad.H!MTB"
        threat_id = "2147923946"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hiddad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 26 8d 19 85 42 09 d2 9d 5d 03 2e 94 5d 85 ea 04 05 9d 55 06 f1 01 05 2e 46 f2 d3 da f8 00 00 01 31 01 33 81 42 eb d3 99 f8 04 10 4d 1d a8 42}  //weight: 1, accuracy: High
        $x_1_2 = {20 68 d0 f8 90 13 20 46 88 47 90 b9 20 68 29 46 32 46 43 46 d0 f8 78 c1 20 46 e0 47 05 46 20 68 d0 f8 90 13 20 46 88 47 20 b1 20 68 41 6c 20 46 88 47}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

