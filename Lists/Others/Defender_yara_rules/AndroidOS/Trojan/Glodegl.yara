rule Trojan_AndroidOS_Glodegl_A_2147895310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Glodegl.A"
        threat_id = "2147895310"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Glodegl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "chmod -R 777 /data/data/com.gtomato.talkbox" ascii //weight: 1
        $x_1_2 = "AmbienceRecordFileName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

