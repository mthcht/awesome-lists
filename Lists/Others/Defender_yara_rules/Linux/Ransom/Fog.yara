rule Ransom_Linux_Fog_A_2147921856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Fog.A!MTB"
        threat_id = "2147921856"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Fog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 5c 24 d0 48 89 6c 24 d8 4c 89 64 24 e0 4c 89 6c 24 e8 41 89 f4 4c 89 74 24 f0 4c 89 7c 24 f8 48 81 ec 28 01 00 00 ?? ?? ?? ?? ?? 89 fe 41 89 fd 49 89 d7 41 89 ce 4c 89 44 24 08 48 89 ef 44 89 4c 24 04}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 57 08 ff c1 89 d0 48 c1 ea 20 88 47 08 88 57 0c c1 e8 08 c1 ea 08 88 47 09 c1 e8 08 88 57 0d c1 ea 08 88 47 0a 88 57 0e c1 e8 08 c1 ea 08 88 47 0b 88 57 0f 48 83 c7 08 83 f9 19}  //weight: 1, accuracy: High
        $x_1_3 = ".fog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

