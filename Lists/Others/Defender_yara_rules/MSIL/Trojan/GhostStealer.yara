rule Trojan_MSIL_GhostStealer_MB_2147897692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GhostStealer.MB!MTB"
        threat_id = "2147897692"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GhostStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 0b 08 28 ?? ?? ?? 0a 2d 10 08 11 0b 28 ?? ?? ?? 0a 16 13 18 dd 1e 03 00 00 11 13 7b 2c 00 00 04 11 0b 6f ?? ?? ?? 0a 26 14 13 0c 72 d7 06 00 70 73 c0 00 00 0a 13 0d 11 07 13 0e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

