rule Trojan_Win32_MinerCrypt_SN_2147773197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MinerCrypt.SN!MTB"
        threat_id = "2147773197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MinerCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 8b 3c 24 83 c4 04 29 c0 21 c0 21 f6 e8 ?? 00 00 00 21 f0 46 09 c6 31 3a 89 f0 21 c6 42 29 f0 81 e8 ?? ?? ?? ?? 21 c6 39 da 75 ?? 81 c0 ?? ?? ?? ?? 48 c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

