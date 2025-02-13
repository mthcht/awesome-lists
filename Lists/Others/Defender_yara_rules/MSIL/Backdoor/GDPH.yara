rule Backdoor_MSIL_GDPH_RDA_2147844562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/GDPH.RDA!MTB"
        threat_id = "2147844562"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GDPH"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1b0679be72ad976a" wide //weight: 1
        $x_1_2 = "~/wwww.aspx" wide //weight: 1
        $x_1_3 = "~/test333.aspx" wide //weight: 1
        $x_1_4 = "~/test222.aspx" wide //weight: 1
        $x_1_5 = "payload" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

