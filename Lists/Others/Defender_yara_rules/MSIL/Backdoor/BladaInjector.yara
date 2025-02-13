rule Backdoor_MSIL_BladaInjector_2147742421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/BladaInjector!MTB"
        threat_id = "2147742421"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BladaInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 72 57 03 00 70 ?? 72 5f 03 00 70 ?? 72 6b 03 00 70 ?? 72 73 03 00 70}  //weight: 1, accuracy: Low
        $x_1_2 = {13 04 16 13 05 30 00 72 ?? ?? 00 70 0a 72 ?? ?? 00 70 0b 72 ?? ?? 00 70 0c 72 ?? ?? 00 70 0d 73 ?? 00 00 0a 13 04 16 13 05}  //weight: 1, accuracy: Low
        $x_1_3 = {28 3e 00 00 0a [0-10] 28 3f 00 00 0a [0-10] 28 40 00 00 0a [0-10] 14 14}  //weight: 1, accuracy: Low
        $x_1_4 = {9c a2 14 14 28 ?? 00 00 0a 26 30 00 28 ?? 00 00 0a 9c 25 17 12 07 28 ?? 00 00 0a 9c 25 18 12 07 28 ?? 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

