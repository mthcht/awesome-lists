rule Trojan_MSIL_Sakeeya_CNP_2147842147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Sakeeya.CNP!MTB"
        threat_id = "2147842147"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sakeeya"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 05 02 28 ?? ?? ?? ?? 13 04 28 ?? ?? ?? ?? 11 05 11 04 16 11 04 8e b7 6f ?? ?? ?? ?? 6f ?? ?? ?? ?? 0a 06 0d}  //weight: 5, accuracy: Low
        $x_1_2 = "Cr7Ronaldo" wide //weight: 1
        $x_1_3 = "ziden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

