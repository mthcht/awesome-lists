rule Backdoor_MSIL_Sposa_KA_2147896229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Sposa.KA!MTB"
        threat_id = "2147896229"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sposa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 10 11 11 91 13 12 08 11 12 6f ?? 00 00 0a 00 11 11 17 58 13 11 11 11 11 10 8e 69 32 e2}  //weight: 10, accuracy: Low
        $x_1_2 = "ConvertToShellcode" ascii //weight: 1
        $x_1_3 = "ShellcodeRDI_x64.bin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

