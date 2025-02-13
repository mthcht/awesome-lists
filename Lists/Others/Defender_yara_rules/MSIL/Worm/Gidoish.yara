rule Worm_MSIL_Gidoish_A_2147684884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Gidoish.A"
        threat_id = "2147684884"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gidoish"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu" wide //weight: 1
        $x_1_2 = "Z29sZGZpc2ggYm93bA==" wide //weight: 1
        $x_1_3 = "ZGlhbW9uZCByaW5n" wide //weight: 1
        $x_1_4 = "|#Network|@" wide //weight: 1
        $x_1_5 = "BoatKiller" ascii //weight: 1
        $x_1_6 = "BotKill" ascii //weight: 1
        $x_1_7 = {44 4c 45 78 65 63 00}  //weight: 1, accuracy: High
        $x_1_8 = {53 74 61 72 74 41 6e 74 69 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

