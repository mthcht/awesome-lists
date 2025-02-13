rule Trojan_Win32_ArkeiSpyLoader_LK_2147842685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArkeiSpyLoader.LK!MTB"
        threat_id = "2147842685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArkeiSpyLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c0 e0 04 2c 10 0a c3 32 c1 32 c7 88 06 32 e8 83 c6 02 83 c5 02 eb 0e 8a c8 bf 01 00 00 00 fe c9 c0 e1 04 0a cb 8a 02 84 c0 75 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

