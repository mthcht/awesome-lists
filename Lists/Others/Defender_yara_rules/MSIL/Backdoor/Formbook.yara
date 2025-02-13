rule Backdoor_MSIL_Formbook_NJ_2147823617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Formbook.NJ!MTB"
        threat_id = "2147823617"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 ff 03 3e 09 1f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 35 01 00 00 23 01 00 00 ad 04 00 00 df 0e 00 00 57 09 00 00 35 00 00 00 9f 03 00 00 1c 00 00 00 3b 00 00 00 08 00 00 00 01 00 00 00 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

