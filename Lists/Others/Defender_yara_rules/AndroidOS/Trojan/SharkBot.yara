rule Trojan_AndroidOS_SharkBot_M_2147831842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SharkBot.M"
        threat_id = "2147831842"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SharkBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ScanAppInstallActivityOk" ascii //weight: 1
        $x_1_2 = "WILL KILL" ascii //weight: 1
        $x_2_3 = "Lcom/mbkristine8/cleanmaster" ascii //weight: 2
        $x_1_4 = "1234567890qwertyuioplkjhgfdsazxcvbnm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SharkBot_U_2147836436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SharkBot.U"
        threat_id = "2147836436"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SharkBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+MexfEnBZA7q7iZMuUPE2bpWWq7dZXL2urW+z97dpchqWh4hWOgUnbCk4z+Hbza8" ascii //weight: 1
        $x_1_2 = "LMDOverlay not bound" ascii //weight: 1
        $x_1_3 = "show hidden file" ascii //weight: 1
        $x_1_4 = "{upload-url}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SharkBot_H_2147836445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SharkBot.H"
        threat_id = "2147836445"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SharkBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "In what city or town did your mother and father meet" ascii //weight: 1
        $x_1_2 = "package recerver data" ascii //weight: 1
        $x_1_3 = "scan isntall apk" ascii //weight: 1
        $x_1_4 = "question anser" ascii //weight: 1
        $x_1_5 = "root =" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

