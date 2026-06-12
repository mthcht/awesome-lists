rule Trojan_MacOS_SuspHiddenCurlDownload_A_2147971519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspHiddenCurlDownload.A"
        threat_id = "2147971519"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspHiddenCurlDownload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl -o " wide //weight: 1
        $x_1_2 = "curl -so " wide //weight: 1
        $x_3_3 = "/Library/Application Support/.com.apple." wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

