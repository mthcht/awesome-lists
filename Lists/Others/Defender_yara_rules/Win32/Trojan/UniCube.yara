rule Trojan_Win32_UniCube_MA_2147840708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UniCube.MA!MTB"
        threat_id = "2147840708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UniCube"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c2 99 be e8 03 00 00 f7 fe 89 44 24 1c 3b d9 7e ?? 8d a4 24 00 00 00 00 8a 44 24 1c f6 e9 02 c2 28 04 29 41 3b cb 7c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

