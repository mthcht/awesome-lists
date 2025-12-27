rule Trojan_Win64_NoroBot_GXF_2147955928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NoroBot.GXF!MTB"
        threat_id = "2147955928"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NoroBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 b8 00 08 00 00 33 d2 48 8d 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 41 b8 00 08 00 00 33 d2 48 8d 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 41 b8 00 08 00 00 33 d2 48 8d 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 41 b8 00 08 00 00 33 d2 48 8d 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 41 b8 00 08 00 00 33 d2 48 8d 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 41 b8 00 08 00 00 33 d2 48 8d 0d}  //weight: 10, accuracy: Low
        $x_1_2 = "captchanom.top" wide //weight: 1
        $x_1_3 = {69 00 6e 00 73 00 70 00 65 00 63 00 74 00 67 00 75 00 61 00 72 00 61 00 6e 00 74 00 65 00 65 00 2e 00 6f 00 72 00 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

