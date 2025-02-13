rule Trojan_Linux_WellMess_A_2147762398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/WellMess.A!MTB"
        threat_id = "2147762398"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "WellMess"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 3a 2f 53 65 72 76 65 72 2f 42 6f 74 55 49 2f 41 70 70 5f 44 61 74 61 2f 54 65 6d 70 2f [0-32] 2f 73 72 63 2f [0-32] 2e 67 6f 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = "runtime.injectglist" ascii //weight: 1
        $x_1_3 = ".hijacked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_WellMess_A_2147762398_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/WellMess.A!MTB"
        threat_id = "2147762398"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "WellMess"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/home/ubuntu/GoProject/src/bot/botlib.wellMess" ascii //weight: 1
        $x_1_2 = "main.getIP" ascii //weight: 1
        $x_1_3 = "botlib.GetRandomBytes" ascii //weight: 1
        $x_1_4 = "/bot/botlib.SendMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

