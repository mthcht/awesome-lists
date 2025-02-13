rule Backdoor_MSIL_Quasarat_A_2147725184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Quasarat.A!bit"
        threat_id = "2147725184"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasarat"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 64 65 73 63 72 65 76 65 61 62 63 00}  //weight: 1, accuracy: High
        $x_1_2 = "\\Remote\\QuasarRAT-master" ascii //weight: 1
        $x_1_3 = {00 64 65 73 63 72 65 76 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

