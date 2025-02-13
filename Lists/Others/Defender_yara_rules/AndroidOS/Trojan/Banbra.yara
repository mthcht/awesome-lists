rule Trojan_AndroidOS_Banbra_A_2147837513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Banbra.A"
        threat_id = "2147837513"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Banbra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/mydocs/documents/Services/serviceMagic;" ascii //weight: 2
        $x_2_2 = "Services/serviceConclude;" ascii //weight: 2
        $x_2_3 = "action=checkAP&data=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Banbra_AJ_2147904633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Banbra.AJ!MTB"
        threat_id = "2147904633"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Banbra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/firma/dosicko/communication/Server" ascii //weight: 1
        $x_1_2 = "Server$autoPing" ascii //weight: 1
        $x_1_3 = "getInstalledPackages" ascii //weight: 1
        $x_1_4 = "getRootInActiveWindow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Banbra_G_2147919635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Banbra.G"
        threat_id = "2147919635"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Banbra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "urlStringApiTelegram" ascii //weight: 2
        $x_2_2 = "texModificadox" ascii //weight: 2
        $x_2_3 = "ServiceaLRMA" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

