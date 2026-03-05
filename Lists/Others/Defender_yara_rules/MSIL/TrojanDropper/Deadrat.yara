rule TrojanDropper_MSIL_Deadrat_SN_2147964158_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Deadrat.SN!MTB"
        threat_id = "2147964158"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Deadrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {fe 0c 05 00 fe 0c 08 00 fe 0c 05 00 fe 0c 08 00 91 fe 0c 03 00 fe 0c 08 00 91 61 9c 00 fe 0c 08 00 20 01 00 00 00 d6 fe 0e 08 00 fe 0c 08 00 fe 0c 0a 00 fe 0e 0b 00 fe 0c 0b 00 3e c0 ff ff ff}  //weight: 4, accuracy: High
        $x_2_2 = "$db9364e7-7788-4c64-814a-23c81dbb82ee" ascii //weight: 2
        $x_2_3 = "\\Stub\\obj\\x86\\Debug\\Stub.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

