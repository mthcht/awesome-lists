rule Trojan_Win64_Sigloader_SIB_2147807249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sigloader.SIB!MTB"
        threat_id = "2147807249"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sigloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {77 69 61 6b 79 30 30 ?? 5f [0-10] 2e 64 6c 6c}  //weight: 10, accuracy: Low
        $x_1_2 = {41 8b d7 48 8d 85 ?? ?? ?? ?? bf ?? ?? ?? ?? 8d 4a ?? 89 08 d1 c2 48 83 c0 ?? 48 ff cf 75 ?? 89 b5 ?? ?? ?? ?? 41 8b dd 4c 8d 95 ?? ?? ?? ?? bf ?? ?? ?? ?? 41 89 3a 83 fb ?? 7c ?? 4c 8d 85 ?? ?? ?? ?? 4d 8d 4a ?? 44 8b db [0-10] 41 8b 09 41 8b 00 8d 14 48 3b fa 0f 4c d7 8b fa 41 89 12 49 83 e9 ?? 49 83 c0 ?? 49 ff cb 75 ?? ff c3 49 83 c2 ?? 83 fb ?? 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

