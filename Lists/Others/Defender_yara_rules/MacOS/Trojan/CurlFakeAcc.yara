rule Trojan_MacOS_CurlFakeAcc_ZA_2147969242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/CurlFakeAcc.ZA!MTB"
        threat_id = "2147969242"
        type = "Trojan"
        platform = "MacOS: "
        family = "CurlFakeAcc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl" wide //weight: 1
        $x_1_2 = "/zxc/kito" wide //weight: 1
        $x_10_3 = "szfried.com" wide //weight: 10
        $x_10_4 = "culturabia.com" wide //weight: 10
        $x_10_5 = "scubin.com" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

