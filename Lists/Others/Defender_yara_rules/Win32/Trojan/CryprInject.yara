rule Trojan_Win32_CryprInject_SN_2147758055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryprInject.SN!MTB"
        threat_id = "2147758055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryprInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 44 24 24 50 c6 44 24 2b 6e c6 44 24 2f 32 c6 44 24 22 6f c6 44 24 1c 75 c6 44 24 19 69 ff 15 ?? ?? ?? ?? 0f bf 0d ?? ?? ?? ?? 3b 0d ?? ?? ?? ?? 7f 07 c6 05 ?? ?? ?? ?? d9 8b 1d ?? ?? ?? ?? 8d 4c 24 14 51 50 ff d3 8b f8 b8 ?? ?? 00 00 eb}  //weight: 2, accuracy: Low
        $x_2_2 = {c6 44 24 2a 33 c6 44 24 24 6b c6 44 24 2c 00 c6 44 24 14 56 c6 44 24 17 74 c6 44 24 1d 6c c6 44 24 25 65 c7 44 24 10 ?? ?? ?? ?? c6 44 24 29 6c b9 4a 01 00 00 39 05 ?? ?? ?? ?? 75 0b 8b d1 66 39 15 ?? ?? ?? ?? 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

