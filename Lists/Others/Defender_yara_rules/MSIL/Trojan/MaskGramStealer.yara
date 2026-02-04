rule Trojan_MSIL_MaskGramStealer_AMR_2147962337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MaskGramStealer.AMR!MTB"
        threat_id = "2147962337"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MaskGramStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 05 11 05 06 6f ?? 00 00 0a 00 11 05 07 6f ?? 00 00 0a 00 11 05 17 6f ?? 00 00 0a 00 11 05 17 6f ?? 00 00 0a 00 11 05 16 6f ?? 00 00 0a 00 11 05 0c 08 28 ?? 00 00 0a 0d 00 09 14 fe 01 16 fe 01 13 07 11 07 2d 05 1e 13 06}  //weight: 2, accuracy: Low
        $x_1_2 = "config.cfg" wide //weight: 1
        $x_1_3 = "Nologo" wide //weight: 1
        $x_1_4 = "E:VBScript" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

