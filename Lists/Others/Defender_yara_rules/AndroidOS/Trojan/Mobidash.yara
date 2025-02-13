rule Trojan_AndroidOS_Mobidash_T_2147848863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mobidash.T"
        threat_id = "2147848863"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mobidash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2cCwWzQRgnmrEHEQR9JwRQ==" ascii //weight: 1
        $x_1_2 = "stuntmaster.db" ascii //weight: 1
        $x_1_3 = "zLxqZhZinYbAucqKbyxukg==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

