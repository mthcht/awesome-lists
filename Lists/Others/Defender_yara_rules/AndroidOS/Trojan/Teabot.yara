rule Trojan_AndroidOS_Teabot_A_2147786792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Teabot.A"
        threat_id = "2147786792"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Teabot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lvideo/fantasy/amount/api" ascii //weight: 1
        $x_1_2 = "getPhonesInSet" ascii //weight: 1
        $x_1_3 = "agentsomeone" ascii //weight: 1
        $x_1_4 = "addresssorry" ascii //weight: 1
        $x_2_5 = "AJjNtDuRzLiNoLkHqEbFcMcPpWeNfUjSk" ascii //weight: 2
        $x_2_6 = "AOtEoWmZpLfKlAmQeQlGtKcAgAeCmHkInRwLfKdNoDwUbQaUk" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

