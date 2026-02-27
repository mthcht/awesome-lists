rule Trojan_MSIL_CrysomeLoader_SX_2147963708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CrysomeLoader.SX!MTB"
        threat_id = "2147963708"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrysomeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {06 2d 07 72 ?? ?? 00 70 2b 15 02 7b ?? 00 00 04 6f ?? 00 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 02 7b ?? 00 00 04 6f ?? 00 00 06 2d 03}  //weight: 20, accuracy: Low
        $x_10_2 = "/create /tn \"CrysomeLoader\" /tr \"" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

