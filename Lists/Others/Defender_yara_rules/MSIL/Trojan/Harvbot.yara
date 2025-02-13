rule Trojan_MSIL_Harvbot_B_2147706588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Harvbot.B"
        threat_id = "2147706588"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Harvbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 00 75 00 70 00 64 00 61 00 74 00 65 00 ?? ?? 21 00 73 00 79 00 6e 00 ?? ?? 21 00 75 00 64 00 70 00 ?? ?? 21 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {70 00 63 00 6e 00 61 00 6d 00 65 00 3d 00 ?? ?? 26 00 62 00 6f 00 74 00 76 00 65 00 72 00 3d 00 ?? ?? 26 00 63 00 6f 00 75 00 6e 00 74 00 72 00 79 00 3d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

