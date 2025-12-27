rule Ransom_Win64_Vortex_MX_2147947892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Vortex.MX!MTB"
        threat_id = "2147947892"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Vortex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "vcryx.exe" wide //weight: 5
        $x_1_2 = "VortexCry" wide //weight: 1
        $x_1_3 = "$028c95e9-bd03-4ab1-a20a-6e55e289eb0e" ascii //weight: 1
        $x_3_4 = "vcry.dll" wide //weight: 3
        $x_1_5 = "myself.dll" ascii //weight: 1
        $x_1_6 = "VortexSecOps" ascii //weight: 1
        $x_1_7 = "encryped" ascii //weight: 1
        $x_1_8 = "$cb36fa65-c3e9-4af7-b00f-e232a5c85f2f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

