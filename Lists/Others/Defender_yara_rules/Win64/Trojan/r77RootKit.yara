rule Trojan_Win64_r77RootKit_A_2147850683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/r77RootKit.A!MTB"
        threat_id = "2147850683"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "r77RootKit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f 10 00 0f 10 48 10 48 8d 80 ?? ?? ?? ?? 0f 11 42 80 0f 10 40 a0 0f 11 4a ?? 0f 10 48 b0 0f 11 42 a0 0f 10 40 c0 0f 11 4a b0 0f 10 48 d0 0f 11 42 c0 0f 10 40 e0 0f 11 4a d0 0f 10 48 f0 0f 11 42 e0 0f 11 4a f0 48 83 e9}  //weight: 2, accuracy: Low
        $x_2_2 = "R77.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_r77RootKit_C_2147850684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/r77RootKit.C!MTB"
        threat_id = "2147850684"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "r77RootKit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SOFTWARE\\$77config" wide //weight: 2
        $x_2_2 = "ReflectiveDllMain" ascii //weight: 2
        $x_2_3 = "\\.\\pipe\\$77control_redirect" wide //weight: 2
        $x_2_4 = "\\.\\pipe\\$77childproc" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_r77RootKit_MK_2147956087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/r77RootKit.MK!MTB"
        threat_id = "2147956087"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "r77RootKit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_25_1 = {8b 46 3c 0f b7 c9 8b 44 30 78 2b 4c 30 10 8b 44 30 1c 8d 04 88 8b 04 30 03 c6}  //weight: 25, accuracy: High
        $x_10_2 = {0f b7 c9 6b d1 ?? 0f b7 c6 48 3b c8 8b 4d f8 89 55 d8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

