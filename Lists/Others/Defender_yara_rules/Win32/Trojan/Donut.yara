rule Trojan_Win32_Donut_CB_2147839731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Donut.CB!MTB"
        threat_id = "2147839731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gnirtSdaolnwoD" wide //weight: 1
        $x_1_2 = "gnirtS46esaBmorF" wide //weight: 1
        $x_1_3 = "CyberSECx/RTK_Adv_DInvoke_B64_Binary" wide //weight: 1
        $x_1_4 = "Cyberdyne" wide //weight: 1
        $x_1_5 = "peelS" wide //weight: 1
        $x_1_6 = "SM_LASTSM_x64.exe" ascii //weight: 1
        $x_1_7 = "T3PR94FN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Donut_AMAB_2147853389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Donut.AMAB!MTB"
        threat_id = "2147853389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f3 2b fb 8b e9 8a 04 37 30 06 46 83 ed 01}  //weight: 1, accuracy: High
        $x_1_2 = {03 cf 03 c6 c1 c7 05 33 f9 c1 c6 08 33 f0 c1 c1 10 03 c7 03 ce c1 c7 07 c1 c6 0d 33 f8 33 f1 c1 c0 10 83 6c 24 30 01 75 d7 8b 6c 24 28 89 4c 24 14 33 c9 89 74 24 20 89 7c 24 18 89 44 24 1c 8b 44 8d 00 31 44 8c 14 41 83 f9 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

