rule Trojan_MSIL_BlackFus_A_2147739943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BlackFus.A"
        threat_id = "2147739943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlackFus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 1f 20 2f ?? 07 08 18 5b 03 08 18 6f ?? ?? ?? ?? 1f 10 28 ?? ?? ?? ?? 9c 2b ?? 08 18 5b 1f 10 59 0d 06 09 03 08 18 6f ?? ?? ?? ?? 1f 10 28 ?? ?? ?? ?? 07 09 07 8e 69 5d 91 61 d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

