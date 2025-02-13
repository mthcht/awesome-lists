rule Trojan_Win32_DragonRank_PA_2147926042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DragonRank.PA!MTB"
        threat_id = "2147926042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DragonRank"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-32] 2e 00 [0-8] 2f 00 7a 00 7a 00 31 00 2e 00 70 00 68 00 70 00}  //weight: 2, accuracy: Low
        $x_1_2 = "\\HttpModRespDLLx86.pdb" ascii //weight: 1
        $x_1_3 = "MJ12bot|msnbot|Yahoo|bingbot|google|YandexBot|DotBot" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

