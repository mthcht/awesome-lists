rule Trojan_Win32_BazzarLoader_KM_2147775329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BazzarLoader.KM!MTB"
        threat_id = "2147775329"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BazzarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Fuck Def" ascii //weight: 1
        $x_1_2 = "tXg>>osixDUSTk8" ascii //weight: 1
        $x_1_3 = {c1 e9 02 f3 ab 8b ca 83 e1 03 f3 aa 8d 45 ?? 89 5d ?? 50 53 ff 75 ?? 6a 4c 68 ?? ?? ?? ?? ff 75 ?? e8 ?? ?? ?? ?? 85 c0 5f 74 ?? 8b 45 ?? ff 30 50 ff 75 ?? 53 6a 01 53 ff 75 ?? e8 ?? ?? ?? ?? 85 c0 0f 95 c0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

