rule Trojan_MSIL_StealerBot_B_2147944220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerBot.B"
        threat_id = "2147944220"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "WFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhY" wide //weight: 2
        $x_2_2 = "QnJDb3df" wide //weight: 2
        $x_1_3 = "cm9vdFxTZWN1" wide //weight: 1
        $x_1_4 = "SXNBZG1pblBy" wide //weight: 1
        $x_1_5 = "U0VMRUNUICog" wide //weight: 1
        $x_1_6 = "V2luMzJfcHJv" wide //weight: 1
        $x_1_7 = "SEtFWV9MT0NB" wide //weight: 1
        $x_1_8 = "e0ZERDM5QUQwLTIz" wide //weight: 1
        $x_1_9 = {06 08 1f 20 58 8f ?? ?? ?? ?? 25 47 06 08 1f 20 5d 91 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

