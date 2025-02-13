rule Trojan_AndroidOS_Zitmo_A_2147648443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Zitmo.A"
        threat_id = "2147648443"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Zitmo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://softthrifty.com/security.jsp" ascii //weight: 1
        $x_1_2 = "activation_promt" ascii //weight: 1
        $x_1_3 = "systemsecurity6/gms/SmsReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Zitmo_B_2147648444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Zitmo.B"
        threat_id = "2147648444"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Zitmo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&from=%s&text=%s" ascii //weight: 1
        $x_1_2 = "?to=%s&i=%s&m=%s" ascii //weight: 1
        $x_1_3 = "&f=1" ascii //weight: 1
        $x_1_4 = "FirstRun" ascii //weight: 1
        $x_1_5 = "FireGetRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Zitmo_B_2147648444_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Zitmo.B"
        threat_id = "2147648444"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Zitmo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "to=%s&i=%s&m=%s&aid=%s&h=%s&v=%s" ascii //weight: 1
        $x_1_2 = "kavdata.db" ascii //weight: 1
        $x_1_3 = "h=-q--=----tq--t-q=p-q=:-==q/q/qrqoqu-=t-i=qnq-gq=-sqm=-sq.-=c-=qo-mq/=-qzq.-q=p=qh-p=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Zitmo_A_2147834452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Zitmo.A!MTB"
        threat_id = "2147834452"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Zitmo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendInintSms" ascii //weight: 1
        $x_1_2 = "setNotFirstLaunch" ascii //weight: 1
        $x_1_3 = "sendSmsIfEnabled" ascii //weight: 1
        $x_1_4 = "com/security/service" ascii //weight: 1
        $x_1_5 = "sendSmsAnyway" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Zitmo_B_2147838433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Zitmo.B!MTB"
        threat_id = "2147838433"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Zitmo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "com/systemsecurity6/gms" ascii //weight: 10
        $x_10_2 = "TotalHideSms" ascii //weight: 10
        $x_1_3 = "softthrifty.com/security.jsp" ascii //weight: 1
        $x_1_4 = "ExtractNumberFromMessage" ascii //weight: 1
        $x_1_5 = "SmsBlockerThread" ascii //weight: 1
        $x_1_6 = "SendControlInformation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

