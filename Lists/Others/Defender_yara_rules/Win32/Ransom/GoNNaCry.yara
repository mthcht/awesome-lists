rule Ransom_Win32_GoNNaCry_DA_2147763576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GoNNaCry.DA!MTB"
        threat_id = "2147763576"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GoNNaCry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Go build ID:" ascii //weight: 2
        $x_1_2 = "Oops, All your important files are encrypted !" ascii //weight: 1
        $x_1_3 = "All your files have been encrypted with strong encryption algorithm" ascii //weight: 1
        $x_1_4 = "GoNNaCry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

