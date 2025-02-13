rule Trojan_AndroidOS_Spynote_B_2147751000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.B!MTB"
        threat_id = "2147751000"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Lyps/eton/application/" ascii //weight: 10
        $x_10_2 = "Ltneilc/ssecca/etomer/tneilc/" ascii //weight: 10
        $x_5_3 = "com.xxx.broadcast.xxx" ascii //weight: 5
        $x_5_4 = "/base.apk" ascii //weight: 5
        $x_1_5 = "key_logger_online_start" ascii //weight: 1
        $x_1_6 = "file_manager_write_file" ascii //weight: 1
        $x_1_7 = "camera_manager_capture" ascii //weight: 1
        $x_1_8 = "upload_file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Spynote_A_2147751132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.A!MTB"
        threat_id = "2147751132"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Ln/s/app/aServiceSocket;" ascii //weight: 5
        $x_5_2 = "com.xxx.broadcast.xxx" ascii //weight: 5
        $x_1_3 = "key_logger0x00x0LogOnline0x00x0" ascii //weight: 1
        $x_1_4 = "Terminal0x00x0Success0x00x0" ascii //weight: 1
        $x_1_5 = "Microphone0x00x0busy0x00x0Exception0x00x0null" ascii //weight: 1
        $x_1_6 = "CallPhone0x00x0Success0x00x0null" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Spynote_D_2147783187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.D"
        threat_id = "2147783187"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo \"Do I have root?\" >/system/sd/temporary.txt" ascii //weight: 1
        $x_1_2 = "/AudioRecorder.wav" ascii //weight: 1
        $x_1_3 = "ArrayDns_Key" ascii //weight: 1
        $x_1_4 = "Name_Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Spynote_E_2147783188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.E"
        threat_id = "2147783188"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "root@" ascii //weight: 1
        $x_1_2 = "Can't get location by any one" ascii //weight: 1
        $x_1_3 = "/system/bin/screencap -p /sdcard/rootSU.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Spynote_E_2147783188_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.E"
        threat_id = "2147783188"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "this app does not support emulator devices" ascii //weight: 1
        $x_1_2 = "to Allow app, disable firewall first." ascii //weight: 1
        $x_1_3 = "Click: [Delete]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Spynote_A_2147783398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.A"
        threat_id = "2147783398"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VHhUeFQ=" ascii //weight: 1
        $x_1_2 = "U3RhcnROZXdTY2Fu" ascii //weight: 1
        $x_1_3 = "passgmal" ascii //weight: 1
        $x_1_4 = "needdone" ascii //weight: 1
        $x_1_5 = "Recovergmal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Spynote_A_2147783398_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.A"
        threat_id = "2147783398"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "API_SET_ACCOUNT_NICKNAME" ascii //weight: 1
        $x_1_2 = "appsinfo_full/" ascii //weight: 1
        $x_1_3 = "perms_list_full/" ascii //weight: 1
        $x_1_4 = "API_START_POINT_DONATION" ascii //weight: 1
        $x_1_5 = "net/axel/app/serses" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Spynote_F_2147788029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.F"
        threat_id = "2147788029"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lspymax/stub7/ClassGen12" ascii //weight: 1
        $x_1_2 = "canGoBack" ascii //weight: 1
        $x_1_3 = "spymax.stub7.suffix" ascii //weight: 1
        $x_1_4 = "/ClassGen3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Spynote_H_2147789050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.H"
        threat_id = "2147789050"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Regnew" ascii //weight: 1
        $x_1_2 = "ReqiesteNewJob" ascii //weight: 1
        $x_1_3 = "ActivSend" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Spynote_L_2147793531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.L"
        threat_id = "2147793531"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcmf0/c3b5bm90zq/patch/" ascii //weight: 2
        $x_2_2 = "Lcom/android/tester/" ascii //weight: 2
        $x_1_3 = "CAMCORDER" ascii //weight: 1
        $x_1_4 = "/Screenshots" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Spynote_G_2147832617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.G"
        threat_id = "2147832617"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Afterinstalloption" ascii //weight: 2
        $x_2_2 = "SCRActivity" ascii //weight: 2
        $x_2_3 = "singimallisten" ascii //weight: 2
        $x_2_4 = "revocerclick" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Spynote_H_2147832946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.H!MTB"
        threat_id = "2147832946"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GPSCAN" ascii //weight: 1
        $x_1_2 = "com.andscan.betar.calcolator" ascii //weight: 1
        $x_1_3 = "WackMeUpJob" ascii //weight: 1
        $x_1_4 = "MainReflectorScan" ascii //weight: 1
        $x_1_5 = "acomelotor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Spynote_J_2147836727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.J"
        threat_id = "2147836727"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/exit/chat/" ascii //weight: 2
        $x_2_2 = "b0false" ascii //weight: 2
        $x_1_3 = "OpWin" ascii //weight: 1
        $x_1_4 = "null & null" ascii //weight: 1
        $x_1_5 = "PANG !!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Spynote_I_2147837161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.I"
        threat_id = "2147837161"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GetRequierdPrims" ascii //weight: 2
        $x_2_2 = "ToAskNew" ascii //weight: 2
        $x_2_3 = "_ask_remove_" ascii //weight: 2
        $x_2_4 = "AskKeyPrim" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Spynote_K_2147838968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.K"
        threat_id = "2147838968"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/mobihk/v/kforniwwsw0;" ascii //weight: 2
        $x_2_2 = "g/ch2.ygdyegphp?sygdyegsl=" ascii //weight: 2
        $x_2_3 = "ygdyeghttp:ygdyeg//wwwygdyeg.mobiygdyeghok.nygdyeget/chygdye" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Spynote_PH_2147853125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.PH"
        threat_id = "2147853125"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "acercreatingj59727" ascii //weight: 1
        $x_1_2 = "cvsacercreatingj59722" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Spynote_PH_2147853125_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.PH"
        threat_id = "2147853125"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MTU0LjIxNC4zMi4z" ascii //weight: 1
        $x_1_2 = "Grab And GO v" ascii //weight: 1
        $x_1_3 = "app.home-aaa.icu/" ascii //weight: 1
        $x_1_4 = "MjAyLjg3LjIyMS4yMzc" ascii //weight: 1
        $x_1_5 = "Grab n Go v" ascii //weight: 1
        $x_1_6 = "plus.elected.costm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_Spynote_BT_2147888995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.BT"
        threat_id = "2147888995"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HSwKyqbHgA" ascii //weight: 1
        $x_1_2 = "MZlgMirNmv" ascii //weight: 1
        $x_1_3 = "qwerty21345hjdnjd" ascii //weight: 1
        $x_1_4 = "74e8d204618c8d65a19463aebeb36708" ascii //weight: 1
        $x_1_5 = "74e9d53c90ce6f109f76f2abf8652c1e" ascii //weight: 1
        $x_1_6 = "74f11b1985126275" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_Spynote_PY_2147890031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.PY"
        threat_id = "2147890031"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rugby.bible.costm" ascii //weight: 1
        $x_1_2 = "www.singapore-mall.com" ascii //weight: 1
        $x_1_3 = "MTU0LjM5LjE1OC4zMw" ascii //weight: 1
        $x_1_4 = "center.beastality.wan.RECORD" ascii //weight: 1
        $x_1_5 = "MTU0LjM5LjE1OC4zOA==" ascii //weight: 1
        $x_1_6 = "conflictss1" ascii //weight: 1
        $x_1_7 = "altered.independently.optional.RECORD" ascii //weight: 1
        $x_1_8 = "sri.survivors.concert.RECORD" ascii //weight: 1
        $x_1_9 = "cartridge.sullivan.pussy" ascii //weight: 1
        $x_1_10 = "MTc1LjQxLjIxLjQ0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_Spynote_L_2147891908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.L!MTB"
        threat_id = "2147891908"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "screenshotresult" ascii //weight: 1
        $x_1_2 = "getrequierdprims" ascii //weight: 1
        $x_1_3 = "getmet2" ascii //weight: 1
        $x_1_4 = "ask_battary" ascii //weight: 1
        $x_1_5 = "isemu_div_id_lator" ascii //weight: 1
        $x_1_6 = "ActivSend" ascii //weight: 1
        $x_1_7 = "/Config/sys/apps/log/log-" ascii //weight: 1
        $x_1_8 = "VHhUeFQ=" ascii //weight: 1
        $x_1_9 = "AskKeyPrim" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_AndroidOS_Spynote_C_2147894953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.C"
        threat_id = "2147894953"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MY_VPN_NOTIFICATION_ID" ascii //weight: 1
        $x_1_2 = "to Block app, disable firewall first" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Spynote_RH_2147919905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.RH"
        threat_id = "2147919905"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mmarddarmjttjxekirjtsuhcczdhdbdqgrnxmtsoxmsexjmdro6lbmNu18" ascii //weight: 1
        $x_1_2 = "pdbafmdoec1020" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Spynote_OT_2147921652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spynote.OT"
        threat_id = "2147921652"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ddmzzxagqaksjgapeeuortvipvudlpcvjcuhhpuikesqmbylfj22Over" ascii //weight: 1
        $x_1_2 = "itsdvqjkid1016" ascii //weight: 1
        $x_1_3 = "jfjmohifgm1022" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

