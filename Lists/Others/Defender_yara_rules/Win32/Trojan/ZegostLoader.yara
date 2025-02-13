rule Trojan_Win32_ZegostLoader_LK_2147841406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZegostLoader.LK!MTB"
        threat_id = "2147841406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZegostLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 b9 2f 04 90 80 2c 11 05 90 90 90 e2 f7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

