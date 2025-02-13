rule Trojan_Win32_PlugxCrypt_BA_2147763865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PlugxCrypt.BA!MTB"
        threat_id = "2147763865"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PlugxCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {99 f7 7c 24 09 00 8b c1 [0-8] 99 [0-5] f7 7c 24 ?? 8a 04 2a 8a 14 31 32 d0 [0-8] 88 14 31 [0-20] 41 3b cf [0-4] 7c}  //weight: 10, accuracy: Low
        $x_10_2 = {99 f7 7c 24 ?? 0a 00 8b c1 [0-10] 99 f7 7c 24 ?? 8a 04 2a 8a 14 31 32 d0 88 14 31 41 3b cf 7c e6}  //weight: 10, accuracy: Low
        $x_1_3 = {85 c0 c6 44 24 [0-2] c6 44 24 [0-2] c6 44 24 [0-2] c6 44 24 [0-2] c6 44 24 [0-2] c6 44 24 [0-2] c6 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

