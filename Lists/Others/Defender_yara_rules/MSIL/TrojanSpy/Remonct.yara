rule TrojanSpy_MSIL_Remonct_A_2147728118_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Remonct.A!bit"
        threat_id = "2147728118"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remonct"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "oI5+vvPXgAbNkuAAovcoNrxa9Skqucwa1GmjJxGoHWL+NbHADRbPY2r0Y1n7HawY+o2eDXEWMn5GP2grgYfcZg==" wide //weight: 2
        $x_2_2 = "qPF81pJ/fSc/izjmmN9d5g==" wide //weight: 2
        $x_1_3 = "Cli3ntInst4ller" ascii //weight: 1
        $x_1_4 = "ST4RTUPKEY" ascii //weight: 1
        $x_1_5 = "ENCRYPTI0NKEY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

