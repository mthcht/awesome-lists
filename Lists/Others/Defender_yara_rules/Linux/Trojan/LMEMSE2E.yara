rule Trojan_Linux_LMEMSE2E_LMEMSE2EMettlesploit_2147766380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/LMEMSE2E!!LMEMSE2EMettlesploit"
        threat_id = "2147766380"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "LMEMSE2E"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lmems e2e testing sig for mettlesploit" ascii //weight: 1
        $x_1_2 = "mettlesploit!" ascii //weight: 1
        $x_1_3 = "/mettle/mettle/src/mettle.c" ascii //weight: 1
        $x_1_4 = "/mettle/mettle/src/main.c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

