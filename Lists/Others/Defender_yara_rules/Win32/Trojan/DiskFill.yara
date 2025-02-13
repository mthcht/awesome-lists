rule Trojan_Win32_DiskFill_GZY_2147905928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DiskFill.GZY!MTB"
        threat_id = "2147905928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DiskFill"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {a4 0b 13 7e ?? f9 32 af ?? ?? ?? ?? 8b c1 82 22 f5 55 25}  //weight: 5, accuracy: Low
        $x_5_2 = {34 4d 4b 52 a8 6f 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

