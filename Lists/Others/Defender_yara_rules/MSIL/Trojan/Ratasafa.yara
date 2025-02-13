rule Trojan_MSIL_Ratasafa_NYP_2147828825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ratasafa.NYP!MTB"
        threat_id = "2147828825"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ratasafa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 54 01 00 0a 0d 08 09 28 ce 01 00 06 09 16 6a 6f 55 01 00 0a 09 13 04 de 1c}  //weight: 1, accuracy: High
        $x_1_2 = {57 1f b6 0b 09 1f 00 00 00 fa 01 33 00 16 c4 00 01 00 00 00 c4 00 00 00 59 00 00 00 e9 00 00 00 d5 01 00 00 3c 01 00 00 47 00 00 00 76 01 00 00 16 00 00 00 fa 00 00 00 42}  //weight: 1, accuracy: High
        $x_1_3 = "/BlackNotepad;component/app.xaml" ascii //weight: 1
        $x_1_4 = "BlackNotepad.exe" ascii //weight: 1
        $x_1_5 = "Savaged.BlackNotepad.Pr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

