rule Trojan_MSIL_Fauppod_HB_2147841764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fauppod.HB!MTB"
        threat_id = "2147841764"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "JumpChess.Properties.Resources" wide //weight: 10
        $x_10_2 = "FlipFlop.Properties.Resources" wide //weight: 10
        $x_1_3 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 1
        $x_1_4 = "System.CodeDom.Compiler" ascii //weight: 1
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "$$method0x600" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Fauppod_CB_2147841765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fauppod.CB!MTB"
        threat_id = "2147841765"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jpkQls6wHKplng7l9fX" ascii //weight: 1
        $x_1_2 = "SystemManager.frmBoard.resources" ascii //weight: 1
        $x_1_3 = "SystemManager.IJSFIHB.resources" ascii //weight: 1
        $x_1_4 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_5 = "DebuggerHiddenAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Fauppod_ABLA_2147841766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fauppod.ABLA!MTB"
        threat_id = "2147841766"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 00 6e 00 6e 00 61 00 4e 00 75 00 64 00 65 00 32 00 00 13 41 00 6e 00 6e 00 61 00 4e 00 75 00 64 00 65 00 37 00 00 13 41 00 6e 00 6e 00 61 00 4e 00 75 00 64 00 65 00 38}  //weight: 1, accuracy: High
        $x_1_2 = {53 00 49 00 4b 00 4a 00 44 00 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

