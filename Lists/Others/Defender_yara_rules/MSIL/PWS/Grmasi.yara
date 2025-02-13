rule PWS_MSIL_Grmasi_YA_2147731263_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Grmasi.YA!MTB"
        threat_id = "2147731263"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Grmasi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Growtopia\\save.dat" wide //weight: 2
        $x_2_2 = "smtp.gmail.com" wide //weight: 2
        $x_1_3 = "SbieDLL.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

