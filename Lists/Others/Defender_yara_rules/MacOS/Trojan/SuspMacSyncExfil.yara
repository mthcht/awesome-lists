rule Trojan_MacOS_SuspMacSyncExfil_A_2147961107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspMacSyncExfil.A"
        threat_id = "2147961107"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspMacSyncExfil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "curl " wide //weight: 4
        $x_4_2 = "-X POST" wide //weight: 4
        $x_1_3 = "--max-time" wide //weight: 1
        $x_1_4 = "api-key:" wide //weight: 1
        $x_1_5 = " http" wide //weight: 1
        $x_5_6 = "-F file=@/tmp/osalogging.zip -F buildtxd=" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

