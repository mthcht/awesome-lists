rule HackTool_MSIL_Binder_C_2147652096_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Binder.gen!C"
        threat_id = "2147652096"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Binder"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 02 8e b7 17 da 0d 0c 2b 12 02 08 02 08 91 (06|07) 08 (06|07) 8e b7 5d 91 61 9c 08 17 d6 0c 08 09 31 ea 02 (0a|0b) 2b 00 (06|07) 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

