rule Backdoor_MSIL_Blacknet_GG_2147786678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Blacknet.GG!MTB"
        threat_id = "2147786678"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blacknet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "BlackNET" ascii //weight: 10
        $x_1_2 = "StartKeylogger" ascii //weight: 1
        $x_1_3 = "SpamEmail" ascii //weight: 1
        $x_1_4 = "Attack" ascii //weight: 1
        $x_1_5 = "Bitcoin" ascii //weight: 1
        $x_1_6 = "wallet" ascii //weight: 1
        $x_1_7 = "clientid=" ascii //weight: 1
        $x_1_8 = "schtasks" ascii //weight: 1
        $x_1_9 = "SELECT * FROM AntivirusProduct" ascii //weight: 1
        $x_1_10 = "/c ping 1.1.1.1 -n" ascii //weight: 1
        $x_1_11 = "remoteshell.php" ascii //weight: 1
        $x_1_12 = "getCommand.php?id=" ascii //weight: 1
        $x_1_13 = "receive.php?command=" ascii //weight: 1
        $x_1_14 = "/upload.php?id=" ascii //weight: 1
        $x_1_15 = "/check_panel.php" ascii //weight: 1
        $x_1_16 = "connection.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

