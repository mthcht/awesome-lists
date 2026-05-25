rule Trojan_MSIL_GremlinStealer_KX_2147970108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GremlinStealer.KX!MTB"
        threat_id = "2147970108"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GremlinStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 72 a8 00 00 70 6f 07 00 00 0a 0b 02 03 61 0c 08 1f 11 5a 1f 1b 5b 0c}  //weight: 5, accuracy: High
        $x_5_2 = {09 16 28 0a 00 00 0a 20 68 dc 2d 7d 61 1f 64 59 13 04 07 09 16 1a 6f 09 00 00 0a 26 09 16 28 0a 00 00 0a 1b 59 20 2f 6a f2 1c 61 13 05 07 11 04 6a 16 6f 08 00 00 0a 26}  //weight: 5, accuracy: High
        $x_2_3 = "TelegramBot" ascii //weight: 2
        $x_2_4 = "MyPrivateServer" ascii //weight: 2
        $x_2_5 = "GetClipboardData" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

