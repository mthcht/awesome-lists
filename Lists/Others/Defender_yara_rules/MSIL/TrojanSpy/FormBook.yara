rule TrojanSpy_MSIL_FormBook_MR_2147781844_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/FormBook.MR!MTB"
        threat_id = "2147781844"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 11 04 18 6f [0-4] 28 [0-4] 28 [0-4] 04 08 6f [0-4] 28 [0-4] 6a 61 b7 28 [0-4] 28 [0-4] 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_FormBook_MS_2147782976_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/FormBook.MS!MTB"
        threat_id = "2147782976"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 01 11 00 6f [0-4] 17 73 [0-4] 13 07 38 [0-4] 11 01 6f [0-4] 13 06 38 [0-4] 28 [0-4] 72 [0-4] 6f [0-4] 13 05 38 [0-4] 11 00 11 03 11 00 6f [0-4] 1e 5b 6f [0-4] 28 [0-4] 38}  //weight: 1, accuracy: Low
        $x_1_2 = {11 07 20 80 00 00 00 6f [0-4] 38 [0-4] 11 08 11 04 20 [0-4] 73 [0-4] 13 03 20 [0-4] 38 [0-4] 28 [0-4] 72 [0-4] 28 [0-4] 13 08 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

