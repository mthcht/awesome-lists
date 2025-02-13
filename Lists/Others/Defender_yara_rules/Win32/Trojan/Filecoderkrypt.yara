rule Trojan_Win32_Filecoderkrypt_SG_2147763883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Filecoderkrypt.SG!MTB"
        threat_id = "2147763883"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoderkrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 ff d7 81 fe ?? ?? ?? ?? 7f 12 46 8b c6 99 83 fa 01 7c ed 7f 07 3d ?? ?? ?? ?? 72 e4}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 57 bf ?? ?? ?? ?? 57 ff 15 ?? ?? ?? ?? ff 75 08 ff 15 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 81 ff ?? ?? ?? ?? 77 04 85 c0 74 de 5f 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

