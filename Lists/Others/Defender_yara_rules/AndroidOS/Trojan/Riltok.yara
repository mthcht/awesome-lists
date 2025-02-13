rule Trojan_AndroidOS_Riltok_B_2147782934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Riltok.B"
        threat_id = "2147782934"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Riltok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "HTTP_REQ_ENTITY_JOIN" ascii //weight: 2
        $x_2_2 = "sendHitGateAPIRequest" ascii //weight: 2
        $x_2_3 = "requests/HitGateRequest" ascii //weight: 2
        $x_2_4 = "getPostParamsUTF8" ascii //weight: 2
        $x_1_5 = "gating.php" ascii //weight: 1
        $x_1_6 = "gate.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Riltok_D_2147843851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Riltok.D"
        threat_id = "2147843851"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Riltok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "move_sms_client" ascii //weight: 2
        $x_2_2 = "push_end_status" ascii //weight: 2
        $x_2_3 = "isRequestKilled" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

