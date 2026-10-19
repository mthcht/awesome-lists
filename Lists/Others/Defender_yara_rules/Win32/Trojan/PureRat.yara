rule Trojan_Win32_PureRat_AR_2147980577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PureRat.AR!MTB"
        threat_id = "2147980577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PureRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 f8 c1 e0 ?? 31 f8 89 c7 c1 ef ?? 31 f8 89 c7 c1 e7 ?? 31 c7 89 f8 32 86 ?? ?? ?? ?? 31 c8 88 04 33 83 c6}  //weight: 10, accuracy: Low
        $x_1_2 = "AmsiScanBuffer" ascii //weight: 1
        $x_1_3 = "amsi.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

