rule Trojan_MacOS_Rustbucket_AP_2147918955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Rustbucket.AP"
        threat_id = "2147918955"
        type = "Trojan"
        platform = "MacOS: "
        family = "Rustbucket"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "downAndExecute" ascii //weight: 1
        $x_1_2 = "com.apple.pdfViewer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Rustbucket_AQ_2147918956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Rustbucket.AQ"
        threat_id = "2147918956"
        type = "Trojan"
        platform = "MacOS: "
        family = "Rustbucket"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-o ErrorCheck.zip" ascii //weight: 1
        $x_1_2 = "down_update_run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Rustbucket_AR_2147918957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Rustbucket.AR"
        threat_id = "2147918957"
        type = "Trojan"
        platform = "MacOS: "
        family = "Rustbucket"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {75 6e 7a 69 70 20 [0-8] 2f 55 73 65 72 73 2f 53 68 61 72 65 64}  //weight: 4, accuracy: Low
        $x_1_2 = {63 68 6d 6f 64 20 2b 78 [0-8] 2f 55 73 65 72 73 2f 53 68 61 72 65 64 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {63 68 6d 6f 64 20 37 [0-8] 2f 55 73 65 72 73 2f 53 68 61 72 65 64 2f}  //weight: 1, accuracy: Low
        $x_2_4 = {6f 70 65 6e 20 [0-8] 2f 55 73 65 72 73 2f 53 68 61 72 65 64 2f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_Rustbucket_AS_2147918958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Rustbucket.AS"
        threat_id = "2147918958"
        type = "Trojan"
        platform = "MacOS: "
        family = "Rustbucket"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.softwaredev.swift-ui-test" ascii //weight: 1
        $x_1_2 = "7L2UQTVP6F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Rustbucket_AU_2147919373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Rustbucket.AU"
        threat_id = "2147919373"
        type = "Trojan"
        platform = "MacOS: "
        family = "Rustbucket"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.howard.toolkit.calendar" ascii //weight: 1
        $x_1_2 = "CUJH6YKSQY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

