rule Ransom_Win64_MagniberShellLoader_LK_2147842677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MagniberShellLoader.LK!MTB"
        threat_id = "2147842677"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MagniberShellLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 fb 04 75 05 40 88 39 eb 05 0f b6 02 88 01 ff c3 48 ff c1 48 ff c2 83 fb 0b 72 e4}  //weight: 1, accuracy: High
        $x_1_2 = {66 c7 40 f0 0f 05 c6 40 f2 c3 48 c7 40 20 0b 00 00 00 c7 40 d8 00 10 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

