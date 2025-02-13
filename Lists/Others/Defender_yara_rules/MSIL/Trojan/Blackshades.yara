rule Trojan_MSIL_Blackshades_AEY_2147831839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blackshades.AEY!MTB"
        threat_id = "2147831839"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blackshades"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 03 d6 17 d6 8d 28 00 00 01 28 ?? ?? ?? 0a 74 09 00 00 1b 0a 02 06 08 03 6f ?? ?? ?? 0a 0d 09 16 2e 06 08 09 d6 0c 2b d1}  //weight: 2, accuracy: Low
        $x_1_2 = "getStreamBytesX" ascii //weight: 1
        $x_1_3 = "gagaehghfxhfx" wide //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "anaga" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

