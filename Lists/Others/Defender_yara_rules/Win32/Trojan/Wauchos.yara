rule Trojan_Win32_Wauchos_GJV_2147905014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wauchos.GJV!MTB"
        threat_id = "2147905014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wauchos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 55 ec a1 ?? ?? ?? ?? 89 82 ?? ?? ?? ?? 8b 4d f0 83 e9 39 0f b6 15 ?? ?? ?? ?? 2b ca 33 c0 89 0d 18 24 42 00 a3}  //weight: 10, accuracy: Low
        $x_1_2 = "sabfra tmeeemhcCmrtjeh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

