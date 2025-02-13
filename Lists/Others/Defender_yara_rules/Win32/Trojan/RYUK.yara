rule Trojan_Win32_RYUK_DSK_2147753508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RYUK.DSK!MTB"
        threat_id = "2147753508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RYUK"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d f4 c1 e9 05 ba 04 00 00 00 c1 e2 00 8b 75 0c 03 0c 16 33 c1 8b 4d f8 2b c8 89 4d f8}  //weight: 2, accuracy: High
        $x_2_2 = "juvinehisivihohicefogavo" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

