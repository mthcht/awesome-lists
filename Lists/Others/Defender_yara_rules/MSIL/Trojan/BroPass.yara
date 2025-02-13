rule Trojan_MSIL_BroPass_GHQ_2147845728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BroPass.GHQ!MTB"
        threat_id = "2147845728"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BroPass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 08 6f 20 ?? ?? 0a 00 06 07 6f ?? ?? ?? 0a 0d 09 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 13 04 11 04 6f ?? ?? ?? 0a 26 00 de 05}  //weight: 10, accuracy: Low
        $x_1_2 = "api.telegram.org/bot6196636801" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

