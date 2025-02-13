rule Backdoor_MSIL_Twient_A_2147721716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Twient.A!bit"
        threat_id = "2147721716"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Twient"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CONNECTED-CUT-" wide //weight: 1
        $x_1_2 = "C:\\Program Files (x86)\\PDTS\\eduClient" wide //weight: 1
        $x_1_3 = "checkpanic" ascii //weight: 1
        $x_1_4 = {43 00 4f 00 4d 00 4d 00 41 00 4e 00 44 00 ?? ?? 43 00 4f 00 4d 00 4d 00 41 00 4e 00 44 00 5f 00 45 00 4e 00 44 00}  //weight: 1, accuracy: Low
        $x_3_5 = "https://twitter.com/eduClient" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

