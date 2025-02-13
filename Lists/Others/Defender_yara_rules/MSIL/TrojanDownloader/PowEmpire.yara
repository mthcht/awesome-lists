rule TrojanDownloader_MSIL_PowEmpire_A_2147847405_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PowEmpire.A!MTB"
        threat_id = "2147847405"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PowEmpire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EkAbgB2AG8AawBl" wide //weight: 2
        $x_2_2 = "BHAGUAdAB" wide //weight: 2
        $x_2_3 = "ABEAGEAdABhAC" wide //weight: 2
        $x_2_4 = "B7ADIAfQB7ADEAfQB7ADAAfQ" wide //weight: 2
        $x_1_5 = "AddScript" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

