rule Trojan_Win32_GenCrypt_A_2147731633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GenCrypt.A"
        threat_id = "2147731633"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GenCrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 c8 40 89 45 c8 6a 32 58 8b 4d c8 66 89 04 4d ?? ?? ?? ?? 8b 45 c8 40 89 45 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

