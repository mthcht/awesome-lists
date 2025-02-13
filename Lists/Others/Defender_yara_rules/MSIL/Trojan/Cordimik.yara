rule Trojan_MSIL_Cordimik_ABEZ_2147838436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cordimik.ABEZ!MTB"
        threat_id = "2147838436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cordimik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 07 16 73 ?? ?? ?? 0a 0c 73 ?? ?? ?? 0a 0d 08 09 6f ?? ?? ?? 0a 04 09 6f ?? ?? ?? 0a 51 de 1e 09 2c 06 09 6f ?? ?? ?? 0a dc}  //weight: 2, accuracy: Low
        $x_1_2 = "GZipStream" ascii //weight: 1
        $x_1_3 = "NebStub.Form1.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

