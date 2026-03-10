rule Ransom_Win64_Natas_MX_2147964441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Natas.MX!MTB"
        threat_id = "2147964441"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Natas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 c7 f4 48 03 fb 33 db 48 8d 4f 0c 48 8b c7 48 3b f9 77 10 81 38 12 5e d9 57 74 7a 48 ff c0 48 3b c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

