rule TrojanClicker_MSIL_NanoBot_MK_2147967337_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/NanoBot.MK!MTB"
        threat_id = "2147967337"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0c 08 6f ?? 00 00 0a 0d 38 ?? 00 00 00 00 02 7b ?? ?? 00 04 09 72 ?? ?? 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 00}  //weight: 10, accuracy: Low
        $x_20_2 = {0a 00 02 7b ?? 00 00 04 09 72 ?? ?? 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 6f 20 00 00 0a 00 02 7b ?? 00 00 04 02 7b ?? 00 00 04 6f}  //weight: 20, accuracy: Low
        $x_5_3 = "SELECT * FROM ViewGio WHERE ID =" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

