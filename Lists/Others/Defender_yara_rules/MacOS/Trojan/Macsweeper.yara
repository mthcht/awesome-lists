rule Trojan_MacOS_Macsweeper_A_2147745267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Macsweeper.A!MTB"
        threat_id = "2147745267"
        type = "Trojan"
        platform = "MacOS: "
        family = "Macsweeper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.iMunizator.iMunizatorDaemon." ascii //weight: 1
        $x_1_2 = "Resources/iMunizatorDaemon.app" ascii //weight: 1
        $x_1_3 = "Resources/iMunizatorCMI.plugin" ascii //weight: 1
        $x_1_4 = "iMunizator/Updater" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Macsweeper_B_2147748635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Macsweeper.B!MTB"
        threat_id = "2147748635"
        type = "Trojan"
        platform = "MacOS: "
        family = "Macsweeper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iMunizatorCMI: Trying to delete files" ascii //weight: 1
        $x_1_2 = "open -a iMunizatorDaemon" ascii //weight: 1
        $x_1_3 = "com.iMunizator.iMunizatorDaemon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_MacOS_Macsweeper_C_2147755729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Macsweeper.C!MTB"
        threat_id = "2147755729"
        type = "Trojan"
        platform = "MacOS: "
        family = "Macsweeper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MacSweeperCMI: Trying to delete files" ascii //weight: 1
        $x_1_2 = "com.KIVViSoftware.MacSweeperDaemon" ascii //weight: 1
        $x_1_3 = "open -a MacSweeperDaemon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_MacOS_Macsweeper_D_2147757269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Macsweeper.D!MTB"
        threat_id = "2147757269"
        type = "Trojan"
        platform = "MacOS: "
        family = "Macsweeper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "purchaiseThread:" ascii //weight: 3
        $x_1_2 = "com.iMunizator.iMunizator" ascii //weight: 1
        $x_1_3 = {69 6d 75 6e 69 7a 61 74 6f 72 2e [0-3] 2f 62 75 79 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_4 = "com.KIVViSoftware.MacSweeperDaemon" ascii //weight: 1
        $x_1_5 = {6d 61 63 73 77 65 65 70 65 72 2e [0-3] 2f 62 75 79 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

