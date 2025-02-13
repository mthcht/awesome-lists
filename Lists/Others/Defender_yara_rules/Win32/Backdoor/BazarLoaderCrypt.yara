rule Backdoor_Win32_BazarLoaderCrypt_SN_2147778354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/BazarLoaderCrypt.SN!MTB"
        threat_id = "2147778354"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "BazarLoaderCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {6a 40 81 cb 00 10 00 00 53 52 6a 00 ff 15 ?? ?? ?? ?? 8b e8 e8 ?? ?? ?? ?? 8b f0}  //weight: 4, accuracy: Low
        $x_4_2 = {50 55 51 53 6a 01 53 52 ff 15 ?? ?? ?? ?? 5f 85 c0 5b 0f 95 c0 5d 83 c4 0c c3}  //weight: 4, accuracy: Low
        $x_2_3 = "Fuck Def" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

