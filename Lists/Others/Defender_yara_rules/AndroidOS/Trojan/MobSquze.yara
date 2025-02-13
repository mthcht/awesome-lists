rule Trojan_AndroidOS_MobSquze_B_2147923395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/MobSquze.B"
        threat_id = "2147923395"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "MobSquze"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "doesStoreMessage" ascii //weight: 2
        $x_2_2 = "notStoringMessage" ascii //weight: 2
        $x_2_3 = "lp.mobsqueeze.com" ascii //weight: 2
        $x_2_4 = "SQUEEZE_REQUEST" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

