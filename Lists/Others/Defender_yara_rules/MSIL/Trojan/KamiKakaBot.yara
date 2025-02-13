rule Trojan_MSIL_KamiKakaBot_MA_2147848222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KamiKakaBot.MA!MTB"
        threat_id = "2147848222"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KamiKakaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 06 02 06 91 20 ?? ?? ?? ?? 61 d2 9c 38 ?? ?? ?? ?? 02 06 02 06 91 20 ?? ?? ?? ?? 61 d2 9c 06 17 58 0a 06 02 8e 69 32 cf}  //weight: 1, accuracy: Low
        $x_1_2 = "78caa7eb-64b7-46f9-8f7d-0922b7891953" ascii //weight: 1
        $x_1_3 = "/sendDocument?chat_id=" wide //weight: 1
        $x_1_4 = "?caption=" wide //weight: 1
        $x_1_5 = "Kami.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

