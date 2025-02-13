rule Ransom_MSIL_AdmnlockCrypt_PA_2147817571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/AdmnlockCrypt.PA!MTB"
        threat_id = "2147817571"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AdmnlockCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".admin1" wide //weight: 1
        $x_1_2 = "delete shadows /all /quiet" wide //weight: 1
        $x_1_3 = "All files are encrypted" wide //weight: 1
        $x_1_4 = "\\!!!Recovery File.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

