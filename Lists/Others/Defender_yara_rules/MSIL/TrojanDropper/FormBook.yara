rule TrojanDropper_MSIL_FormBook_SJ_2147962843_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/FormBook.SJ!MTB"
        threat_id = "2147962843"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 28 05 00 00 06 0c 08 28 07 00 00 06 00 28 12 00 00 0a 28 13 00 00 0a 13 04 12 04 fe 16 0d 00 00 01 6f 14 00 00 0a 72 09 00 00 70 28 09 00 00 0a 28 15 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

