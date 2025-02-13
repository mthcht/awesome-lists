rule Trojan_Win32_SDBBot_AK_2147919159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SDBBot.AK"
        threat_id = "2147919159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SDBBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff 8b d7 4c 8d 3d ?? ?? ?? ?? 0f 1f 80 00 00 00 00 48 8b ca 83 e1 ?? 42 0f b6 ?? ?? 0f b6 84 15 ?? ?? ?? ?? 32 c8 88 8c 15 ?? ?? ?? ?? 48 ff c2 48 83 fa ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b d7 48 8b ca 83 e1 ?? 42 0f b6 ?? ?? 0f b6 84 15 ?? ?? 00 00 32 c8 88 8c 15 ?? ?? 00 00 48 ff c2 48 83 fa ?? 72}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b ca 83 e1 ?? 42 0f b6 ?? ?? 0f b6 84 15 ?? ?? ?? ?? 32 c8 88 8c 15 ?? ?? ?? ?? 48 ff c2 48 83 fa ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SDBBot_AL_2147919160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SDBBot.AL"
        threat_id = "2147919160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SDBBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 1f 40 00 48 8b c2 83 e0 ?? 0f b6 0c 30 0f b6 84 15 fe 00 00 00 32 c8 88 8c 15 ?? ?? 00 00 48 ff c2 48 83 fa ?? 72 [0-64] 66 44 39 34 41 75}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 44 24 30 48 8d 4d d0 48 83 c0 ?? ff d0 0f 10 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

