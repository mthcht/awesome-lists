rule Backdoor_MSIL_Prostbot_A_2147629448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Prostbot.A"
        threat_id = "2147629448"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Prostbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 16 0c 38 36 00 00 00 02 08 6f ?? 00 00 ?? 0d 09 06 08 59 61 d2 13 04 09 1e 63 08 61 d2 13 05 07 08 11 05 1e 62 11 04 60 d1 9d 08 17 58 0c}  //weight: 10, accuracy: Low
        $x_1_2 = "Stasi Bot.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

