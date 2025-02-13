rule Trojan_AndroidOS_Boogr_A_2147752672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Boogr.A!MTB"
        threat_id = "2147752672"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Boogr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "spy.cashnow.ee/api/deviceMessages" ascii //weight: 2
        $x_1_2 = "contacts_calls" ascii //weight: 1
        $x_1_3 = "getandSaveImei" ascii //weight: 1
        $x_1_4 = "WhatsApp/Media/WhatsApp Images" ascii //weight: 1
        $x_1_5 = "Telegram/Telegram Images" ascii //weight: 1
        $x_1_6 = "spydb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Boogr_B_2147762563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Boogr.B!MTB"
        threat_id = "2147762563"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Boogr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "su -c cat /data/data/com.whatsapp/databases/msgstore.db" ascii //weight: 1
        $x_1_2 = "cybercoprahul.in/tracker/scripts/upload.php" ascii //weight: 1
        $x_1_3 = "send_snap.php?id=" ascii //weight: 1
        $x_1_4 = "send_smslist.php?id=" ascii //weight: 1
        $x_2_5 = "/.tracker/.files" ascii //weight: 2
        $x_1_6 = "s.whatsapp.net" ascii //weight: 1
        $x_1_7 = "potentially harmful application has been detected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Boogr_D_2147808781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Boogr.D!MTB"
        threat_id = "2147808781"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Boogr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 05 16 00 13 00 48 00 23 01 ?? ?? 26 01 ?? ?? 00 00 23 52 ?? ?? 12 00 34 50 08 00 22 00 ?? ?? 70 20 ?? ?? 20 00 11 00 dc 03 00 48 49 04 06 00 44 03 01 03 b7 43 8e 33 50 03 02 00 d8 00 00 01 28 ec}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Boogr_E_2147819633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Boogr.E!MTB"
        threat_id = "2147819633"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Boogr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "url.txt" ascii //weight: 1
        $x_1_2 = "Cannot send files from the assets folder" ascii //weight: 1
        $x_1_3 = "Lcom/reza/sh/deviceinfo/DiviceInfo" ascii //weight: 1
        $x_1_4 = "hideicon" ascii //weight: 1
        $x_1_5 = "getdevicefullinfo" ascii //weight: 1
        $x_1_6 = "SendSingleMessage" ascii //weight: 1
        $x_1_7 = "onstartcommand" ascii //weight: 1
        $x_1_8 = "rat.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_AndroidOS_Boogr_H_2147826794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Boogr.H!MTB"
        threat_id = "2147826794"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Boogr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6f 6d 2f 70 72 6f 6a 65 63 74 2f [0-22] 4d 79 4e 6f 74 69 66 69 63 61 74 69 6f 6e 53 65 72 76 69 63 65}  //weight: 1, accuracy: Low
        $x_1_2 = "READ_PHONE_NUMBERS" ascii //weight: 1
        $x_1_3 = "/api/calllog/bot/" ascii //weight: 1
        $x_1_4 = "wpa_supplicant.conf" ascii //weight: 1
        $x_1_5 = "/api/contact/bot/" ascii //weight: 1
        $x_1_6 = "goos.pw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_Boogr_T_2147839020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Boogr.T"
        threat_id = "2147839020"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Boogr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "existpicnic" ascii //weight: 1
        $x_1_2 = "isPriceStartsWithCurrency" ascii //weight: 1
        $x_1_3 = "Lcom/cement/bullet/tiger" ascii //weight: 1
        $x_1_4 = "strugglenotice" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Boogr_I_2147844116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Boogr.I!MTB"
        threat_id = "2147844116"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Boogr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/imonitor/ainfo" ascii //weight: 1
        $x_1_2 = "clipboard.cfg" ascii //weight: 1
        $x_1_3 = "deviceinfo.cfg" ascii //weight: 1
        $x_1_4 = "UpdateWebsiteHistory" ascii //weight: 1
        $x_1_5 = "eammobilephotos/" ascii //weight: 1
        $x_1_6 = "start log sms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

