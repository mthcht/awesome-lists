rule Trojan_AndroidOS_Wilfi_HT_2147927143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Wilfi.HT"
        threat_id = "2147927143"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Wilfi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "195.10.205.223:5000/vanilla" ascii //weight: 1
        $x_1_2 = "Error while sending SMS data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

