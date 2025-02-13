rule Trojan_AndroidOS_HiddenApp_C_2147806380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/HiddenApp.C"
        threat_id = "2147806380"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "HiddenApp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lam/xtrack/LolaActivity" ascii //weight: 1
        $x_1_2 = "xtrack.INTENT_SHOW" ascii //weight: 1
        $x_1_3 = "/SoloActivity;" ascii //weight: 1
        $x_1_4 = "/StereoReceiver;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_HiddenApp_C_2147814874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/HiddenApp.C!MTB"
        threat_id = "2147814874"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "HiddenApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/membersgir/iiapps" ascii //weight: 1
        $x_1_2 = "hiddenAppIcon" ascii //weight: 1
        $x_1_3 = "ResumableSub_Service_Start" ascii //weight: 1
        $x_1_4 = "canOverDrawOtherApps" ascii //weight: 1
        $x_1_5 = "_popuptelegram" ascii //weight: 1
        $x_1_6 = "iiapps/dnormal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_HiddenApp_B_2147814986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/HiddenApp.B!MTB"
        threat_id = "2147814986"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "HiddenApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.la.mi.lamiservice" ascii //weight: 1
        $x_1_2 = "_processdatapush" ascii //weight: 1
        $x_1_3 = "ShowOrHideAppFromLuncher" ascii //weight: 1
        $x_1_4 = "ResumableSub_DownloadFile" ascii //weight: 1
        $x_1_5 = "InstallTarget23AndAbove" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_HiddenApp_D_2147829437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/HiddenApp.D!MTB"
        threat_id = "2147829437"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "HiddenApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ping.confirmid.name/" ascii //weight: 1
        $x_1_2 = "&pndr_install=1" ascii //weight: 1
        $x_1_3 = "/client.config/?app=pndr2&format=json&advert_key=" ascii //weight: 1
        $x_1_4 = "spdyConnection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_HiddenApp_E_2147832598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/HiddenApp.E!MTB"
        threat_id = "2147832598"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "HiddenApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aaapps.list.com.takenote" ascii //weight: 1
        $x_1_2 = "NoteDetailsEditActivity" ascii //weight: 1
        $x_1_3 = "goo.gl/JxXyZI" ascii //weight: 1
        $x_1_4 = "HiddenByApp" ascii //weight: 1
        $x_1_5 = "com.pusslies.onagra.ModeChangedReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

