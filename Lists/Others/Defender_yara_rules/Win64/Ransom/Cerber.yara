rule Ransom_Win64_Cerber_MKV_2147953700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Cerber.MKV!MTB"
        threat_id = "2147953700"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4c 8b 10 4c 33 15 ea 5a 23 00 4c 8b 58 08 49 31 db 48 89 c3 4c 89 d8 49 89 d3 49 f7 e2 4c 8b 53 ?? 49 31 f2 48 89 c6 4c 89 c0 49 89 d0 49 f7 e2 4c 8b 53 ?? 49 31 fa 48 89 c7 4c 89 c8 49 89 d1 49 f7 e2}  //weight: 5, accuracy: Low
        $x_2_2 = "Your files have been encrypted." ascii //weight: 2
        $x_2_3 = "To decrypt them, send 1 Bitcoin" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Cerber_ARAX_2147959853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Cerber.ARAX!MTB"
        threat_id = "2147959853"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".wcry" ascii //weight: 2
        $x_2_2 = "Bitcoin to this Address" ascii //weight: 2
        $x_2_3 = "files are encrypted" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

