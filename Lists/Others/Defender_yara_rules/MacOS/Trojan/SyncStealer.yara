rule Trojan_MacOS_SyncStealer_GVA_2147970685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SyncStealer.GVA!MTB"
        threat_id = "2147970685"
        type = "Trojan"
        platform = "MacOS: "
        family = "SyncStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sh -c " wide //weight: 10
        $x_10_2 = "security find-generic-password" wide //weight: 10
        $x_10_3 = "-wa" wide //weight: 10
        $x_10_4 = "Chrome" wide //weight: 10
        $n_100_5 = "/bin/sh" wide //weight: -100
        $n_100_6 = "/bin/bash" wide //weight: -100
        $n_100_7 = "/bin/zsh" wide //weight: -100
        $n_100_8 = "cursorsandbox" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_MacOS_SyncStealer_GVB_2147970686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SyncStealer.GVB!MTB"
        threat_id = "2147970686"
        type = "Trojan"
        platform = "MacOS: "
        family = "SyncStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sh -c " wide //weight: 10
        $x_10_2 = "security set-generic-password-partition-list -s" wide //weight: 10
        $x_10_3 = "Chrome" wide //weight: 10
        $x_10_4 = "-k" wide //weight: 10
        $x_10_5 = "-a" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_SyncStealer_GVC_2147970687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SyncStealer.GVC!MTB"
        threat_id = "2147970687"
        type = "Trojan"
        platform = "MacOS: "
        family = "SyncStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "310"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "sh -c " wide //weight: 100
        $x_100_2 = "cat" wide //weight: 100
        $x_10_3 = "/Chrome/Default/Cookies" wide //weight: 10
        $x_10_4 = "/Chrome/Default/Web Data" wide //weight: 10
        $x_10_5 = "/Chrome/Default/Login Data" wide //weight: 10
        $x_100_6 = "/tmp/sync1001800/Browsers" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_SyncStealer_GVD_2147970688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SyncStealer.GVD!MTB"
        threat_id = "2147970688"
        type = "Trojan"
        platform = "MacOS: "
        family = "SyncStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sh -c " wide //weight: 10
        $x_10_2 = "ditto -c -k" wide //weight: 10
        $x_10_3 = "--sequesterRsrc " wide //weight: 10
        $x_10_4 = "/tmp/sync1001800/" wide //weight: 10
        $x_10_5 = ".zip" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

