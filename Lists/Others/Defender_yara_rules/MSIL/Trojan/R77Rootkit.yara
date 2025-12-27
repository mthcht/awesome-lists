rule Trojan_MSIL_R77Rootkit_PAGQ_2147956751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/R77Rootkit.PAGQ!MTB"
        threat_id = "2147956751"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "R77Rootkit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DelegateExecute" wide //weight: 1
        $x_2_2 = "<ObfuscatePowershellStringLiterals>" ascii //weight: 2
        $x_2_3 = "GetPowershellCommand" ascii //weight: 2
        $x_1_4 = "C:\\Windows\\System32\\fodhelper.exe" wide //weight: 1
        $x_1_5 = "Stager" wide //weight: 1
        $x_2_6 = {07 02 08 09 08 59 6f ?? 00 00 0a 26 02 09 17 58 11 04 09 59 17 59 6f ?? 00 00 0a 06 28 ?? ?? ?? ?? 13 05 07 11 05 6f ?? 00 00 0a 26 11 04 17 58 0c 2b ad}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

