rule Trojan_MSIL_ProCheck_A_2147745053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ProCheck.A!MSR"
        threat_id = "2147745053"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ProCheck"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ProfileCheck\\obj\\Release\\ProfileCheck.pdb" ascii //weight: 1
        $x_1_2 = "BatchBuildDockingPane" ascii //weight: 1
        $x_1_3 = "created with an evaluation version of CryptoObfuscator" ascii //weight: 1
        $x_1_4 = "_Encrypted$" wide //weight: 1
        $x_1_5 = "UHJvZmlsZUNoZWNrJA==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

