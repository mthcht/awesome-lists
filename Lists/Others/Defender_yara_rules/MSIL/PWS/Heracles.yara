rule PWS_MSIL_Heracles_CFF_2147976796_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Heracles.CFF!MTB"
        threat_id = "2147976796"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "WindowsPassKey.pdb" ascii //weight: 10
        $x_1_2 = "output.txt" wide //weight: 1
        $x_1_3 = "Please enter your login password" wide //weight: 1
        $x_1_4 = "WindowsPassKey.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

