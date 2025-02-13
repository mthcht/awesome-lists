rule Ransom_Win32_MakopCrypt_SN_2147758172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MakopCrypt.SN!MTB"
        threat_id = "2147758172"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MakopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 8d 84 24 ?? ?? ?? ?? 50 ff d7 6a 00 8d 44 24 4c 50 ff d3 6a 00 ff d5 a1 ?? ?? ?? ?? 81 fe ?? ?? ?? ?? 0f 44 05 ?? ?? ?? ?? 46 a3 ?? ?? ?? ?? 81 fe ?? ?? ?? ?? 7c ?? ff d0}  //weight: 2, accuracy: Low
        $x_2_2 = {33 f3 c7 44 24 14 00 00 00 00 33 f7 8b 7c 24 1c 2b fe 89 7c 24 1c 25 ?? ?? ?? ?? 81 6c 24 14 ?? ?? ?? ?? bb ?? ?? ?? ?? 81 44 24 14 ?? ?? ?? ?? 8b 4c 24 14 8b d7 d3 e2 8b c7 03 54 24 24 c1 e8 05 03 44 24 30 33 d0 c7 05 ?? ?? ?? ?? 00 00 00 00 8b 44 24 18 03 c7 33 d0 2b ea 8b 15 ?? ?? ?? ?? 81 fa ?? ?? ?? ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

