rule Backdoor_MSIL_Sanhotan_A_2147683537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Sanhotan.A"
        threat_id = "2147683537"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sanhotan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QUIEN ES TU DIOS" wide //weight: 1
        $x_1_2 = "!UPDIR-T" wide //weight: 1
        $x_1_3 = "XAT:NICK" wide //weight: 1
        $x_1_4 = "SanuFloodHilo" ascii //weight: 1
        $x_1_5 = "sanCam" ascii //weight: 1
        $x_1_6 = "CopyFromScreen" ascii //weight: 1
        $x_1_7 = "SAN:" wide //weight: 1
        $x_1_8 = "SCR:" wide //weight: 1
        $x_1_9 = "CAM:" wide //weight: 1
        $x_1_10 = "XAO:" wide //weight: 1
        $x_1_11 = "OIR:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

