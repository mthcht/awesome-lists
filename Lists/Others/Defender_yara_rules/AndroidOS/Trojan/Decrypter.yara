rule Trojan_AndroidOS_Decrypter_UT_2147919241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Decrypter.UT"
        threat_id = "2147919241"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Decrypter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zsTMtB3rtR3g78aZ2dK0z3mFQa1kmAAJMcfj2jOSE" ascii //weight: 1
        $x_1_2 = "sendPhotoFeedback::url:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

