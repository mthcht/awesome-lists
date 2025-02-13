rule Backdoor_MSIL_Redcap_AR_2147832248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Redcap.AR!MTB"
        threat_id = "2147832248"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 13 04 00 11 04 28 1a 00 00 0a 00 00 09 6f}  //weight: 2, accuracy: High
        $x_1_2 = "PS2exe.exe" wide //weight: 1
        $x_1_3 = "PS2exe.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

