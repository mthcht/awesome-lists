rule Ransom_MSIL_Clinix_PA_2147754971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Clinix.PA!MTB"
        threat_id = "2147754971"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Clinix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 53 00 74 00 61 00 72 00 74 00 20 00 4d 00 65 00 6e 00 75 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 5c 00 [0-48] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "\\rundll32-.txt" wide //weight: 1
        $x_1_3 = "wscript.exe \"%temp%\\invs.vbs\" \"%temp%\\java2.bat" wide //weight: 1
        $x_1_4 = "wscript.exe \"%appdata%\\invs.vbs\" \"%appdata%\\java2.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

