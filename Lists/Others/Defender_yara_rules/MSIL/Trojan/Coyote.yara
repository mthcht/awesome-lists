rule Trojan_MSIL_Coyote_U_2147947398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coyote.U"
        threat_id = "2147947398"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coyote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "180"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "UIAutomationClient" ascii //weight: 20
        $x_20_2 = "FromBase64String" ascii //weight: 20
        $x_20_3 = "Costura" ascii //weight: 20
        $x_20_4 = "mscoree.dll" ascii //weight: 20
        $x_20_5 = "WatsonTcpClient" ascii //weight: 20
        $x_20_6 = "GetProcessesByName" ascii //weight: 20
        $x_20_7 = "WindowInteropHelper" ascii //weight: 20
        $x_20_8 = "FF48DBA4-60EF-4201-AA87-54103EEF594E" wide //weight: 20
        $x_20_9 = {06 2d 06 16 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 2c 06 16 28 00 0a}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

