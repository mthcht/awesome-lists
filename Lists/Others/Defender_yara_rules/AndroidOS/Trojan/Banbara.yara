rule Trojan_AndroidOS_Banbara_V_2147852038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Banbara.V"
        threat_id = "2147852038"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Banbara"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sicrediov" ascii //weight: 1
        $x_1_2 = "wss://api.bananasplit.shop/ws" ascii //weight: 1
        $x_1_3 = "6499ff8fbc2f8bc08dd73342" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Banbara_H_2147916237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Banbara.H"
        threat_id = "2147916237"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Banbara"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ComandoDeletarAll" ascii //weight: 2
        $x_2_2 = "traverseNodeInicio" ascii //weight: 2
        $x_2_3 = "api/v1/Pegasus/DeletarComandoTodos" ascii //weight: 2
        $x_2_4 = "RecursividadeText" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

