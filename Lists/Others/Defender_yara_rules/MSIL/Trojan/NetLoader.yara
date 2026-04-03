rule Trojan_MSIL_NetLoader_RR_2147966251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NetLoader.RR!MTB"
        threat_id = "2147966251"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 12 a2 11 21 1a 72 f2 [0-2] 70 a2 11 21 1b 28 28 [0-2] 0a 6f 29 00 00 0a a2 11 21 1c 72 0c [0-2] 70 a2 11 21 1d 11 0c a2 11 21 1e 72 [0-2] 00 70 a2 11 21 28 [0-2] 00 0a 6f [0-2] 00 0a 26 2b 0a 11 05 11 12 6f 07 01 00 0a 26 de 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

