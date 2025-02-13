rule Trojan_Win32_DeapaxCrypt_RD_2147765452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DeapaxCrypt.RD!MTB"
        threat_id = "2147765452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DeapaxCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ea cc 34 00 00 89 55 [0-5] 8b 45 [0-5] 33 [0-7] 89 45 [0-5] 8b 4d [0-5] 8b 95 ?? ?? ?? ?? 8b 45 [0-5] 89 04 8a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

