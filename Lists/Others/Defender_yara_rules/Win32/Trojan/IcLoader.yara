rule Trojan_Win32_IcLoader_RG_2147893258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcLoader.RG!MTB"
        threat_id = "2147893258"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 15 3c 40 65 00 8b 4c 24 14 51 ff 15 3c 40 65 00 5f 5e 5b 83 c4 10 c3 90 90 90 55 8b ec 51 68 90 b9 85 00 e8 12 fe ff ff e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

