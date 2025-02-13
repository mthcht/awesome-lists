rule Backdoor_MSIL_Plupay_A_2147724560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Plupay.A!bit"
        threat_id = "2147724560"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Plupay"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "animalcollectiononline.com/inst_n.php" wide //weight: 1
        $x_1_2 = "plugandplay.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

