rule Trojan_MSIL_BlueBeam_AAA_2147972882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BlueBeam.AAA!AMTB"
        threat_id = "2147972882"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlueBeam"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Desktop\\ActivitySurrogateSelector\\LoadLibrary\\obj\\Debug\\LoadLibrary.pdb" ascii //weight: 10
        $x_2_2 = "CREATE_SUSPENDED" ascii //weight: 2
        $x_2_3 = "AMSI_RESULT_CLEAN" ascii //weight: 2
        $x_2_4 = "AddVectoredExceptionHandler" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

