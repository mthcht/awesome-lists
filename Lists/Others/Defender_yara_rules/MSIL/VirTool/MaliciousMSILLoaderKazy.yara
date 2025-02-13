rule VirTool_MSIL_MaliciousMSILLoaderKazy_A_2147695057_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/MaliciousMSILLoaderKazy.A"
        threat_id = "2147695057"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MaliciousMSILLoaderKazy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {91 61 d2 9c 11 ?? 17 58 13}  //weight: 10, accuracy: Low
        $x_10_2 = {69 59 11 05 58 11 04 11 05 91 9c 11 05 17 58 13 05 11 05 11 04 8e 69 32 d8 09 17 58 0d 09 20}  //weight: 10, accuracy: High
        $x_1_3 = "dohteMteG" wide //weight: 1
        $x_1_4 = "Resize" ascii //weight: 1
        $x_1_5 = "redaoLyzaK" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

