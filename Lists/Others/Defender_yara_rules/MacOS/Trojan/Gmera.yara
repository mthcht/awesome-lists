rule Trojan_MacOS_Gmera_A_2147745837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Gmera.A!MTB"
        threat_id = "2147745837"
        type = "Trojan"
        platform = "MacOS: "
        family = "Gmera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "owpqkszz.info/link.php" ascii //weight: 1
        $x_1_2 = "com.appIe.stockf.stocks" ascii //weight: 1
        $x_1_3 = "9Stockfoli11AppDelegateC" ascii //weight: 1
        $x_1_4 = "Developer ID Application: Nikolay Shmatko (57LR7SY7LF)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Gmera_B_2147756815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Gmera.B!MTB"
        threat_id = "2147756815"
        type = "Trojan"
        platform = "MacOS: "
        family = "Gmera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stepbystepby.com/link.php" ascii //weight: 1
        $x_1_2 = "com.trading.Licatrade.app" ascii //weight: 1
        $x_1_3 = "9Licatrade11AppDelegate" ascii //weight: 1
        $x_1_4 = "Developer ID Application: Andrey Novoselov (M8WVDT659T)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Gmera_C_2147760170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Gmera.C!MTB"
        threat_id = "2147760170"
        type = "Trojan"
        platform = "MacOS: "
        family = "Gmera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cointrazer" ascii //weight: 1
        $x_1_2 = "nagsrsdfsudinasa.com/link.php" ascii //weight: 1
        $x_1_3 = "com.appIe.Trezarusios.Trezarus" ascii //weight: 1
        $x_1_4 = "A265HSB92F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

