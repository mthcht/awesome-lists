rule Trojan_AndroidOS_SMforw_B_2147789170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SMforw.B"
        threat_id = "2147789170"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SMforw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "regCustomer" ascii //weight: 1
        $x_1_2 = "/ConnMachine" ascii //weight: 1
        $x_1_3 = "&telcompany=" ascii //weight: 1
        $x_1_4 = "sendPoke" ascii //weight: 1
        $x_1_5 = "=receivesms&telnum=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SMforw_C_2147789256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SMforw.C"
        threat_id = "2147789256"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SMforw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hp_getsmsblockstate.php?telnum=" ascii //weight: 1
        $x_1_2 = "getTelCompany" ascii //weight: 1
        $x_1_3 = "?type=join&telnum=" ascii //weight: 1
        $x_1_4 = "buileClient" ascii //weight: 1
        $x_1_5 = "postGPSData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SMforw_F_2147794299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SMforw.F"
        threat_id = "2147794299"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SMforw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ConvHelpers" ascii //weight: 2
        $x_2_2 = "Lcom/e4a/runtime/helpers/StmtHelpers" ascii //weight: 2
        $x_1_3 = "smsColumn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

