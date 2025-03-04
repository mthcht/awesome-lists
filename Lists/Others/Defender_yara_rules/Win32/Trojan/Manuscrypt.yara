rule Trojan_Win32_ManusCrypt_CAZZ_2147843979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ManusCrypt.CAZZ!MTB"
        threat_id = "2147843979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ManusCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 01 76 ?? 8a 11 30 54 08 ff 83 c0 ff 83 e8 01 74 0c 8a 54 08 01 30 14 08 83 e8 01 75 f4 8a 54 08 01 30 14 08 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

