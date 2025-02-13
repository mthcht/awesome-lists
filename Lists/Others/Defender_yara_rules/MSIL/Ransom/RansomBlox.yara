rule Ransom_MSIL_RansomBlox_PA_2147845043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/RansomBlox.PA!MTB"
        threat_id = "2147845043"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RansomBlox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 2e 00 65 00 78 00 65 00 [0-6] 2d 00 [0-2] 20 00 2d 00 74 00 20 00 30 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Your all file is encrypted by RanSom" wide //weight: 1
        $x_1_3 = {5c 52 57 61 72 65 5c 52 57 61 72 65 5c [0-16] 5c 52 6f 57 61 72 65 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

