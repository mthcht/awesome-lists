rule Ransom_Win64_DelShad_SG_2147894742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/DelShad.SG!MTB"
        threat_id = "2147894742"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "DelShad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Data\\rick.png" ascii //weight: 1
        $x_2_2 = "/c vssadmin.exe delete shadows /all /quiet" ascii //weight: 2
        $x_1_3 = "BCryptEncrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

