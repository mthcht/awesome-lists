rule Trojan_AndroidOS_Banjeon_A_2147934502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Banjeon.A"
        threat_id = "2147934502"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Banjeon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mythisapp/connection/ConnectionResultBean" ascii //weight: 2
        $x_2_2 = "mythisapp/task/LongConnectionEngine" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

