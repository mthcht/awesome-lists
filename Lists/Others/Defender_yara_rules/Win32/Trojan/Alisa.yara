rule Trojan_Win32_Alisa_GHJ_2147844194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alisa.GHJ!MTB"
        threat_id = "2147844194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alisa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b0 65 88 44 24 ?? 88 44 24 ?? 88 44 24 ?? 8d 44 24 ?? 50 51 c6 44 24 ?? 43 c6 44 24 ?? 72 c6 44 24 ?? 61 c6 44 24 ?? 74 c6 44 24 ?? 45 c6 44 24 ?? 76 c6 44 24 ?? 6e c6 44 24 ?? 74 c6 44 24 ?? 41 88 5c 24}  //weight: 10, accuracy: Low
        $x_1_2 = "Ch7Demo6.EXE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alisa_GNW_2147895516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alisa.GNW!MTB"
        threat_id = "2147895516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alisa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 10 8b 44 24 14 89 54 24 18 99 2b c2 8b f8 8b c5 99 2b c2 8b 54 24 54 d1 ff d1 f8 2b c7 03 c8 8b 44 24 18 89 4c 24 1c 03 cd 03 c2 89 4c 24 24 8b 4c 24 70 89 44 24 20 8b 06 51 8b ce}  //weight: 10, accuracy: High
        $x_1_2 = "CListCtrl_test" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

