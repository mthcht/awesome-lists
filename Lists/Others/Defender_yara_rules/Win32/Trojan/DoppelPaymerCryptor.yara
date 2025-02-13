rule Trojan_Win32_DoppelPaymerCryptor_2147762402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DoppelPaymerCryptor!MTB"
        threat_id = "2147762402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DoppelPaymerCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e4 b9 ?? ?? ?? ?? 2b 4d f4 8b 55 ec 8a 1c 02 8b 75 e8 88 1c 06 01 c8 8b 4d f0 39 c8 89 45 e4 74 ?? eb ?? 31 c0 89 45 e4 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

