rule Ransom_Win64_Cartel_AA_2147822381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Cartel.AA!MTB"
        threat_id = "2147822381"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Cartel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 4c 24 ?? 48 8b 54 24 ?? 0f b6 0c 0a 03 c1 0f b6 4c 24 ?? 03 c1 25 ff 00 00 00 88 44 24 ?? 0f b7 44 24 ?? 48 8b 4c 24 ?? 0f b6 04 01 88 44 24 ?? 0f b6 44 24 ?? 0f b7 4c 24 ?? 48 8b 54 24 ?? 4c 8b 44 24 ?? 41 0f b6 04 00 88 04 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "/c vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Cartel_SA_2147838821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Cartel.SA"
        threat_id = "2147838821"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Cartel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rathbuige" ascii //weight: 1
        $x_1_2 = "servicemain" ascii //weight: 1
        $x_1_3 = "svchostpushserviceglobals" ascii //weight: 1
        $x_1_4 = "vssadmin.exe delete shadows /all /quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Cartel_MK_2147839475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Cartel.MK!MTB"
        threat_id = "2147839475"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Cartel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8b c2 48 98 48 8b ?? ?? ?? ?? ?? ?? 48 23 ?? ?? ?? 48 8b c1 48 8b ?? ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 48 33 c8 48 8b c1 8b 8c 24 ?? ?? ?? ?? 8b 94 24 ?? ?? ?? ?? 03 d1 8b ca 48 63 c9 48 8b 94 24 ?? ?? ?? ?? 48 89 ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

