rule Backdoor_MSIL_XWormRat_SDA_2147919115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWormRat.SDA!MTB"
        threat_id = "2147919115"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 07 72 11 00 00 70 28 ?? ?? ?? 0a 13 08}  //weight: 1, accuracy: Low
        $x_1_2 = {28 0d 00 00 0a 2c 08 11 08 28 ?? ?? ?? 0a 00 11 08 28 ?? ?? ?? 0a 2d 0d 11 08 28 0e 00 00 06 28 0f 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

