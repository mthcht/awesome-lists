rule Ransom_Win64_Skruppy_AB_2147977534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Skruppy.AB!MTB"
        threat_id = "2147977534"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Skruppy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Your files are encrypted by skruppy!" ascii //weight: 2
        $x_2_2 = "Contact via ig: @bartvus_" ascii //weight: 2
        $x_2_3 = "Warning! this will kill your PC if you choose 'yes'" ascii //weight: 2
        $x_2_4 = "Are you sure that you want this? [yes/no]" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

