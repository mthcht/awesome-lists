rule TrojanDropper_MSIL_BlaGen_ARA_2147837234_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/BlaGen.ARA!MTB"
        threat_id = "2147837234"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlaGen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 16 0b 2b 55 02 07 6f ?? ?? ?? ?? 0c 08 1f 61 32 1b 08 1f 7a 30 16 08 1f 0d 58 0d 09 1f 7a 31 05 09 1f 1a 59 0d 06 07 09 d1 9d 2b 29 08 1f 41 32 20 08 1f 5a 30 1b 08 1f 0d 58 13 04 11 04 1f 5a 31 07 11 04 1f 1a 59 13 04 06 07 11 04 d1 9d 2b 04 06 07 08 9d 07 17 58 0b 07 02 6f ?? ?? ?? ?? 32 a2}  //weight: 2, accuracy: Low
        $x_2_2 = "temp\\Assembly.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

