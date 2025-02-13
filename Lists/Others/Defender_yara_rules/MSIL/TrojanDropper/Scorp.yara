rule TrojanDropper_MSIL_Scorp_ARA_2147848468_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Scorp.ARA!MTB"
        threat_id = "2147848468"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scorp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\Code\\GTAV\\TetstAutorun\\TetstAutorun\\obj\\Release\\TetstAutorun.pdb" ascii //weight: 2
        $x_2_2 = "Test.lnk" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

