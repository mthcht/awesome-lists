rule Trojan_MSIL_PswStealer_PAHR_2147965700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PswStealer.PAHR!MTB"
        threat_id = "2147965700"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PswStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendZip" ascii //weight: 1
        $x_2_2 = "set_UseShellExecute" ascii //weight: 2
        $x_1_3 = "<tempLoginDataPath>" ascii //weight: 1
        $x_1_4 = "<TakeSession>" ascii //weight: 1
        $x_1_5 = "<SaveToFile>" ascii //weight: 1
        $x_1_6 = "<checkWallets>" ascii //weight: 1
        $x_1_7 = "<pwds>" ascii //weight: 1
        $x_2_8 = "<cookies>" ascii //weight: 2
        $x_2_9 = "<loadEncrKeys>" ascii //weight: 2
        $x_1_10 = "csproduct get uuid" wide //weight: 1
        $x_1_11 = "get_BrowserName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

