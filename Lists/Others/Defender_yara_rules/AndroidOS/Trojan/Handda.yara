rule Trojan_AndroidOS_Handda_A_2147832147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Handda.A"
        threat_id = "2147832147"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Handda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "chmod -R 4755 /system/bin/screencap" ascii //weight: 2
        $x_2_2 = "Lcom/photo/androida/MainActivity;" ascii //weight: 2
        $x_2_3 = "ex_isupload" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

