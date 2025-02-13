rule Trojan_Win64_PrintNightmare_A_2147850692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PrintNightmare.A!MTB"
        threat_id = "2147850692"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PrintNightmare"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {45 33 c9 89 44 24 48 48 89 44 24 64 48 8d 1d ?? ?? ?? ?? 89 44 24 6c 4c 8d 44 24 38 0f 57 c0 48 89 5c 24 38 48 8d 05 ?? ?? ?? ?? c7 44 24 60 00 00 01 00 41 8d 51 01 48 89 44 24 40 33 c9 f3 0f 7f 44 24 50 ff 15 ?? ?? ?? ?? 4c 8d 4c 24 30 48 89 5c 24 30 41 b8 03 00 00 00 c7 44 24 20 01 00 00 00 48 8d 15 f5 da 02 00 33 c9 ff 15 1d}  //weight: 2, accuracy: Low
        $x_2_2 = "nightmare" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PrintNightmare_SA_2147895788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PrintNightmare.SA!MTB"
        threat_id = "2147895788"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PrintNightmare"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Administrators" wide //weight: 1
        $x_1_2 = "\\nightmare\\x64\\Release\\nightmare.pdb" ascii //weight: 1
        $x_1_3 = "nightmare.dll" ascii //weight: 1
        $x_1_4 = "Batman42!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

