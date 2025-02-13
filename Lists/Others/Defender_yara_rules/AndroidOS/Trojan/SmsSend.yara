rule Trojan_AndroidOS_SmsSend_GV_2147785361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSend.GV!MTB"
        threat_id = "2147785361"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSend"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com/piripipiapps/delifun" ascii //weight: 2
        $x_2_2 = "trackInfo" ascii //weight: 2
        $x_1_3 = "SMS_SENT" ascii //weight: 1
        $x_1_4 = "Felicitaciones! Activaste el servicio" ascii //weight: 1
        $x_1_5 = "http://apk.sound.com.py/track.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SmsSend_GH_2147787858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSend.GH!MTB"
        threat_id = "2147787858"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSend"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://m.mworld.vn/MWorld30/data20.xm?a=getip&g=3&sex=Android" ascii //weight: 2
        $x_2_2 = "SMS_SENT_" ascii //weight: 2
        $x_1_3 = "resource.dat" ascii //weight: 1
        $x_1_4 = "aSMS" ascii //weight: 1
        $x_1_5 = {e1 bb a8 6e 67 20 64 e1 bb a5 6e 67 20 c4 91 c3 a3 20 c4 91 c6 b0 e1 bb a3 63 20 6b c3 ad 63 68 20 68 6f e1 ba a1 74 20 74 68 c3 a0 6e 68 20 63 c3 b4 6e 67 2c 20 63 68 c3 ba 63 20 62 e1 ba a1 6e 20 76 75 69 20 76 e1 ba bb 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SmsSend_D_2147795317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSend.D"
        threat_id = "2147795317"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSend"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PVMobAd_App_Key" ascii //weight: 1
        $x_1_2 = "SEND_CENTER_CODE" ascii //weight: 1
        $x_1_3 = "makeSureUpdate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsSend_B_2147825011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSend.B!MTB"
        threat_id = "2147825011"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSend"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/tomkoole/smsping" ascii //weight: 1
        $x_1_2 = "CreateUrlEvento" ascii //weight: 1
        $x_1_3 = "HiloLeeSMS" ascii //weight: 1
        $x_1_4 = "RedirijoSMSPing" ascii //weight: 1
        $x_1_5 = "LeerSms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_SmsSend_A_2147845866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSend.A"
        threat_id = "2147845866"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSend"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ARENA EXCITE" ascii //weight: 1
        $x_1_2 = "GAL CANTIK" ascii //weight: 1
        $x_1_3 = "Ppageromo" ascii //weight: 1
        $x_1_4 = "OntkenningDis" ascii //weight: 1
        $x_1_5 = "ON GAME KISS" ascii //weight: 1
        $x_1_6 = "GIRL CANTIK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_SmsSend_A_2147845866_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSend.A"
        threat_id = "2147845866"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSend"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/WEB-INF/pages/play/wap3/bill.jspp" ascii //weight: 2
        $x_2_2 = "wapBillUrl" ascii //weight: 2
        $x_2_3 = "/wap/n10345332d2c502111125.jsp" ascii //weight: 2
        $x_2_4 = "wapAfterMiguSdkSuc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsSend_E_2147849806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSend.E!MTB"
        threat_id = "2147849806"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSend"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/agewap/ero/gallery/GalleryActivity" ascii //weight: 1
        $x_1_2 = "sendTextMessage" ascii //weight: 1
        $x_1_3 = "file.lock" ascii //weight: 1
        $x_1_4 = "/ImageAdapter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

