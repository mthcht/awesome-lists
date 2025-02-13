rule Trojan_AndroidOS_Opfake_A_2147764682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Opfake.A!MTB"
        threat_id = "2147764682"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Opfake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OutCallReceiver" ascii //weight: 1
        $x_1_2 = "OutMsgReceiver" ascii //weight: 1
        $x_1_3 = "qpclick.com" ascii //weight: 1
        $x_1_4 = "SendActivity" ascii //weight: 1
        $x_1_5 = "setTask.php?id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Opfake_B_2147828654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Opfake.B!MTB"
        threat_id = "2147828654"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Opfake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/dev/getTask.php" ascii //weight: 1
        $x_1_2 = "andrpay.ru" ascii //weight: 1
        $x_1_3 = "com/apireflectionmanager" ascii //weight: 1
        $x_1_4 = "com/android/system/AppDownloaderActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_Opfake_C_2147829482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Opfake.C!MTB"
        threat_id = "2147829482"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Opfake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net/android/app/InstallActivity" ascii //weight: 1
        $x_1_2 = "net/android/app/LoaderActivity" ascii //weight: 1
        $x_1_3 = "FJe2jsveoHHMpxvV" ascii //weight: 1
        $x_1_4 = "sendTextMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Opfake_D_2147829483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Opfake.D!MTB"
        threat_id = "2147829483"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Opfake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "html/android/install/Download" ascii //weight: 2
        $x_2_2 = "/HtmlSMSActivity" ascii //weight: 2
        $x_1_3 = "readOptionsXml" ascii //weight: 1
        $x_1_4 = "goMessage" ascii //weight: 1
        $x_1_5 = "sendTextMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Opfake_E_2147834896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Opfake.E!MTB"
        threat_id = "2147834896"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Opfake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%x%b%o%t%0%0%7%" ascii //weight: 1
        $x_1_2 = "bn/save_message.php" ascii //weight: 1
        $x_1_3 = "#m#e#s##s#a#g#e#" ascii //weight: 1
        $x_1_4 = "com/tujtr/rtbrr/adm_reciv" ascii //weight: 1
        $x_1_5 = "/bn/reg.php?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Opfake_F_2147835835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Opfake.F!MTB"
        threat_id = "2147835835"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Opfake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SurpriseService" ascii //weight: 1
        $x_1_2 = "USSD_SEND_RECEIVER" ascii //weight: 1
        $x_1_3 = "&mode=register&country=" ascii //weight: 1
        $x_1_4 = "/controller.php?mode=saveMsg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Opfake_G_2147837863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Opfake.G!MTB"
        threat_id = "2147837863"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Opfake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smsPrices" ascii //weight: 1
        $x_1_2 = ".receivers.AdminTracker" ascii //weight: 1
        $x_1_3 = "com/apps/pack" ascii //weight: 1
        $x_1_4 = "reenableKeyguard" ascii //weight: 1
        $x_1_5 = "getTask.php?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Opfake_H_2147845150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Opfake.H!MTB"
        threat_id = "2147845150"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Opfake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1a 01 00 00 1a 03 01 00 07 24 07 25 74 06 07 00 00 00 1a 01 04 00 1a 03 01 00 07 24 07 25 74 06 07 00 00 00 1a 01 04 00 1a 03 01 00 07 24 07 25 74 06 07 00 00 00 1a 01 03 00 1a 03 01 00 07 24 07 25}  //weight: 1, accuracy: High
        $x_1_2 = {12 0a 12 02 6f 20 01 00 cb 00 15 01 03 7f 6e 20 15 00 1b 00 22 08 18 00 1a 01 40 00 1a 03 47 00 70 30 1c 00 18 03 6e 10 1d 00 08 00 0a 01 38 01 05 00 71 10 24 00 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Opfake_B_2147895734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Opfake.B"
        threat_id = "2147895734"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Opfake"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BOCXC]gOCB?s-m" ascii //weight: 1
        $x_1_2 = "9loyn13zi1wM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Opfake_U_2147896291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Opfake.U"
        threat_id = "2147896291"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Opfake"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[Ljcjcl/tnhkk;" ascii //weight: 2
        $x_2_2 = "vmkrvauio" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Opfake_I_2147915009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Opfake.I!MTB"
        threat_id = "2147915009"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Opfake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net/os/android" ascii //weight: 1
        $x_1_2 = "mxclick.com" ascii //weight: 1
        $x_1_3 = "SMS_SENT" ascii //weight: 1
        $x_1_4 = "USSDDumbExtendedNetworkService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Opfake_TE_2147919240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Opfake.TE"
        threat_id = "2147919240"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Opfake"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ERVdRV8B.QYEQ.V.ERs 5E?O8cmVmj RmOdJ" ascii //weight: 1
        $x_1_2 = "coYu.CmVd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Opfake_OT_2147927142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Opfake.OT"
        threat_id = "2147927142"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Opfake"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "km1mQC?.YVs QdVLCGdOdh" ascii //weight: 1
        $x_1_2 = "oR?d@.QVd?UdCd.1d?" ascii //weight: 1
        $x_1_3 = "mRc?E.c`mYY`)CV.1.VA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

