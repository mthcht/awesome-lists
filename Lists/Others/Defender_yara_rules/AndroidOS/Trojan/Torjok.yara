rule Trojan_AndroidOS_Torjok_A_2147829667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Torjok.A!MTB"
        threat_id = "2147829667"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Torjok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "p-goapk" ascii //weight: 1
        $x_1_2 = "kjs123.sinaapp.com/sdkcfg.php?" ascii //weight: 1
        $x_1_3 = "/sdc/newinit5.php?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

