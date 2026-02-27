rule Trojan_MSIL_ClipBoardLogger_SX_2147963629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBoardLogger.SX!MTB"
        threat_id = "2147963629"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBoardLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {0b 06 07 28 ?? 00 00 0a 2c 4f 07 0a 7e 03 00 00 04 72 ?? ?? 00 70 1b 8d 09 00 00 01 0c 08 16 72 ?? ?? 00 70 a2 08 17 28 ?? 00 00 0a 0d 12 03 72 ?? ?? 00 70 28 08 00 00 0a a2 08 18 72 ?? ?? 00 70 a2 08 19 06 a2 08 1a}  //weight: 20, accuracy: Low
        $x_10_2 = "ClipboardLogger" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

