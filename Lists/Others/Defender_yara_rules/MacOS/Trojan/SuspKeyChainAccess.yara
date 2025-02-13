rule Trojan_MacOS_SuspKeyChainAccess_AX_2147919198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspKeyChainAccess.AX"
        threat_id = "2147919198"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspKeyChainAccess"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "JC_BUNDLE_ID" ascii //weight: 2
        $x_2_2 = "ranrok" ascii //weight: 2
        $x_2_3 = "JC_WORKFLOW_MSG" ascii //weight: 2
        $x_1_4 = "/Library/Keychains/System.keychain" ascii //weight: 1
        $x_1_5 = "/Library/Keychains/login.keychain-db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

