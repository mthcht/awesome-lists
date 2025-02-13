rule Backdoor_MSIL_MessChange_B_2147756789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/MessChange.B!dha"
        threat_id = "2147756789"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MessChange"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 4d 00 53 00 45 00 78 00 63 00 68 00 61 00 6e 00 67 00 65 00 42 00 61 00 63 00 6b 00 65 00 6e 00 64 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

