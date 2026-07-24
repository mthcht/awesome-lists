rule Trojan_Win32_VelleyRAT_GTX_2147974395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VelleyRAT.GTX!MTB"
        threat_id = "2147974395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VelleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 02 99 be ?? ?? ?? ?? f7 fe 83 c2 36 8b 45 e8 0f be 0c 01 33 ca 8b 55 ec 8b 42 08 8b 55 e8 88 0c 10 8b 45 e4 83 c0 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

