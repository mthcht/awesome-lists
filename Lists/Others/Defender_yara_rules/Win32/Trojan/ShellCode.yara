rule Trojan_Win32_ShellCode_EAYU_2147939208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellCode.EAYU!MTB"
        threat_id = "2147939208"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellCode"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 14 10 23 fa 0b f7 0b ce 8b 45 f8 03 45 fc 88 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

