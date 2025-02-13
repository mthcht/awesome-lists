rule Trojan_AndroidOS_Eldorado_A_2147846393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Eldorado.A"
        threat_id = "2147846393"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Eldorado"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setQuintessential" ascii //weight: 1
        $x_1_2 = "syncHarbinger" ascii //weight: 1
        $x_1_3 = "useLangCountryHl" ascii //weight: 1
        $x_1_4 = "ueGqOrnsCy" ascii //weight: 1
        $x_1_5 = "viewSurreptitious" ascii //weight: 1
        $x_1_6 = "saveMellifluous" ascii //weight: 1
        $x_1_7 = "viewElision" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

