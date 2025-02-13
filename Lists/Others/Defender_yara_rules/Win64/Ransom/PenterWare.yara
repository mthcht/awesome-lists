rule Ransom_Win64_PenterWare_GS_2147898764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/PenterWare.GS!MTB"
        threat_id = "2147898764"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "PenterWare"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 0f b6 0c 0e ff c2 44 0f b6 d2 46 8b 1c 90 44 01 df 44 0f b6 e7 46 8b 2c a0 46 89 2c 90 46 89 1c a0 47 8d 14 2b 45 0f b6 d2 46 33 0c 90 44 88 0c 0b 48 ff c1 49 39 c8}  //weight: 1, accuracy: High
        $x_1_2 = "vssadmin.exe delete shadows /all /quiet /?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

