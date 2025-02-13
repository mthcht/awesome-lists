rule Trojan_AndroidOS_MobOkDropper_A_2147745285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/MobOkDropper.A"
        threat_id = "2147745285"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "MobOkDropper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DexClassLoader" ascii //weight: 1
        $x_1_2 = "o%s.dex" ascii //weight: 1
        $x_1_3 = "aHR0cDovL2JiLnJvd3V0ZS5jb20=" ascii //weight: 1
        $x_1_4 = "45.79.19.59" ascii //weight: 1
        $x_1_5 = "L3BnbS9ydC9sZw==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

