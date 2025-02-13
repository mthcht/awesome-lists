rule Trojan_AndroidOS_Mailthief_B_2147831106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mailthief.B!MTB"
        threat_id = "2147831106"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mailthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "camera/normal/RemoteCameraActivity" ascii //weight: 1
        $x_1_2 = "GmailCapture" ascii //weight: 1
        $x_1_3 = "ExecSpoofSms" ascii //weight: 1
        $x_1_4 = "com/fp/WebViewActivity" ascii //weight: 1
        $x_1_5 = "nmgmail.ref" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Mailthief_A_2147894955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mailthief.A"
        threat_id = "2147894955"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mailthief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "new message!. contact name:" ascii //weight: 1
        $x_1_2 = "is NEW -> insert" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

