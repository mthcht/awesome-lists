rule Trojan_Win32_Akorocrypt_B_2147830647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Akorocrypt.B!MTB"
        threat_id = "2147830647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Akorocrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 57 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {80 74 05 ac bc 40 83 f8 14 72 f5}  //weight: 1, accuracy: High
        $x_1_3 = {8b c2 33 d2 f7 f1 8a 44 15 ?? 42 30 04 ?? ?? ?? ?? 72 ed}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

