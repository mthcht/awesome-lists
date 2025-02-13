rule Ransom_MSIL_Cgbog_A_2147839637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cgbog.A!MTB"
        threat_id = "2147839637"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cgbog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 25 26 28 ?? ?? 00 06 25 26 0d 00 09 28 ?? ?? 00 06 25 26 28 ?? ?? 00 06 25 26 13 07 38 10 02 00 00 11 07 28 ?? ?? 00 06 25 26 28 ?? ?? 00 06 25 26 13 04 00 7e ?? ?? 00 04 0a 02 11 04 20}  //weight: 2, accuracy: Low
        $x_1_2 = "RegistryKey" ascii //weight: 1
        $x_1_3 = "DebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

