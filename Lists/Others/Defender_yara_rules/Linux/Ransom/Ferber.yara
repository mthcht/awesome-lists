rule Ransom_Linux_Ferber_A_2147852392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Ferber.A!MTB"
        threat_id = "2147852392"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Ferber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://xxxx.onion/" ascii //weight: 1
        $x_1_2 = "RECOVERY_README" ascii //weight: 1
        $x_1_3 = "DecodingLookupArray" ascii //weight: 1
        $x_1_4 = "://pigetrzlperjreyr3fbytm27bljaq4eungv3gdq2tohnoyfrqu4bx5qd.onion/bt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

