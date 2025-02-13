rule Ransom_AndroidOS_Lucy_B_2147788427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Lucy.B"
        threat_id = "2147788427"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Lucy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "genbj3b60392d222M1a2in3Acti1vity" ascii //weight: 2
        $x_1_2 = "ReqPerm activili down" ascii //weight: 1
        $x_1_3 = "genk0ngn0h04o222R1eq2Pe311rm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

