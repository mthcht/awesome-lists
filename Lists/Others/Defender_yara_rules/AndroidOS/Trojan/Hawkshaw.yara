rule Trojan_AndroidOS_Hawkshaw_A_2147890033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hawkshaw.A"
        threat_id = "2147890033"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hawkshaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "is not a file, aborting upload" ascii //weight: 1
        $x_1_2 = "PushFileTus: Upload starting..." ascii //weight: 1
        $x_1_3 = "AddCallLog: You don't have permission to write call logs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

