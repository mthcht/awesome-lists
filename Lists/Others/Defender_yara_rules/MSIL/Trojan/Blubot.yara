rule Trojan_MSIL_Blubot_ABL_2147846724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blubot.ABL!MTB"
        threat_id = "2147846724"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blubot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0a 16 0b 2b 3a 03 07 6f ?? ?? ?? 0a 1f 61 32 0b 03 07 6f ?? ?? ?? 0a 1f 7a 31 1e 03 07 6f ?? ?? ?? 0a 1f 41 32 10 03 07 6f ?? ?? ?? 0a 1f 3e fe 02 16 fe 01 2b 04 16 2b 01 17 0a 07 17 58 0b 07 03 6f ?? ?? ?? 0a 2f 03 06 2c ba}  //weight: 2, accuracy: Low
        $x_1_2 = "MCBOTALPHA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

