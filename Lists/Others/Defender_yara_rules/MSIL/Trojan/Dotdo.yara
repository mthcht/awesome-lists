rule Trojan_MSIL_Dotdo_AA_2147794050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dotdo.AA!MTB"
        threat_id = "2147794050"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dotdo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {15 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00 04 00 00 00 01 00 00 00 04 00 00 00 02}  //weight: 10, accuracy: High
        $x_3_2 = "\\try\\try\\" ascii //weight: 3
        $x_3_3 = "app.pdb" ascii //weight: 3
        $x_3_4 = "app.Properties.Resources" ascii //weight: 3
        $x_3_5 = "DockStyle" ascii //weight: 3
        $x_3_6 = "DebuggingModes" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

