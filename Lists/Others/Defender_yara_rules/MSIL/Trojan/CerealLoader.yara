rule Trojan_MSIL_CerealLoader_AA_2147982564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CerealLoader.AA!MTB"
        threat_id = "2147982564"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CerealLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 17 58 0a 20 ?? ?? ?? ?? 2b 94 02 15 7d ?? ?? ?? ?? 16 0a 07 20 ?? ?? e0 00 5a 20 ?? dc 70 3b 61}  //weight: 10, accuracy: Low
        $x_8_2 = {1a 34 32 20 ?? 6d 89 30 20 ?? 04 94 0e 61 25 0a 1d 5e}  //weight: 8, accuracy: Low
        $x_2_3 = "Exchange.Data.Transport.ni.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

