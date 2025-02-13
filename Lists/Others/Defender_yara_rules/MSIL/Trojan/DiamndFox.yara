rule Trojan_MSIL_DiamndFox_PA_2147774371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiamndFox.PA!MTB"
        threat_id = "2147774371"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiamndFox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "aHR0cDovLzM3LjEyMC4yMjIuMjQxL2ZzL3dhbGxwYXBlci5qcGVn" wide //weight: 4
        $x_1_2 = "decbytec" wide //weight: 1
        $x_1_3 = "runner" wide //weight: 1
        $x_1_4 = "\\wallpaper.jpeg" wide //weight: 1
        $x_1_5 = "\\IMG.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

