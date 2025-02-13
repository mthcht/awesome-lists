rule Trojan_MSIL_NekoStealer_AAQO_2147891989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NekoStealer.AAQO!MTB"
        threat_id = "2147891989"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NekoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 16 07 1f 0f 1f 10 28 ?? 00 00 0a 06 07 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 1b 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d 09 03 16 03 8e 69 6f ?? 00 00 0a 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

