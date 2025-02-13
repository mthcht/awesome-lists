rule TrojanSpy_AndroidOS_Sandr_A_2147751119_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Sandr.A!MTB"
        threat_id = "2147751119"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Sandr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lnet/droidjack/server/CamSnap;" ascii //weight: 1
        $x_1_2 = "SandroRat_BrowserHistory_Database" ascii //weight: 1
        $x_1_3 = "/WhatsApp/Databases/wams.db" ascii //weight: 1
        $x_1_4 = "INTERCEPT_INCOMING_SMS_NOS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Sandr_B_2147751137_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Sandr.B!MTB"
        threat_id = "2147751137"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Sandr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lnet/droidjack/server/VideoCapDJ;" ascii //weight: 2
        $x_2_2 = "Lnet/droidjack/server/Controller;" ascii //weight: 2
        $x_1_3 = "getOriginatingAddress" ascii //weight: 1
        $x_1_4 = "getInstalledApplications" ascii //weight: 1
        $x_1_5 = "getLaunchIntentForPackage" ascii //weight: 1
        $x_1_6 = "abortBroadcast" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

