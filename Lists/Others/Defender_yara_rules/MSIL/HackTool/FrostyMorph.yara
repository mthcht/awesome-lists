rule HackTool_MSIL_FrostyMorph_A_2147956421_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/FrostyMorph.A!dha"
        threat_id = "2147956421"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FrostyMorph"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Morpher" ascii //weight: 1
        $x_1_2 = "InjectedSeedCipher" ascii //weight: 1
        $x_1_3 = "DecryptString" ascii //weight: 1
        $x_1_4 = "DecryptLong" ascii //weight: 1
        $x_1_5 = "DecryptFloat" ascii //weight: 1
        $x_1_6 = "DecryptInt" ascii //weight: 1
        $x_1_7 = "DecryptArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

