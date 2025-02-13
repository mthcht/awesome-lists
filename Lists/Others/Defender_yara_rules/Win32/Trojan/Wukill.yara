rule Trojan_Win32_Wukill_MA_2147838776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wukill.MA!MTB"
        threat_id = "2147838776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wukill"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {49 d3 7e d0 cc 0b 2d 4a 87 dd d0 f2 a8 af fb 51}  //weight: 5, accuracy: High
        $x_5_2 = {bc 4a 40 00 4c 00 00 00 56 42 35 21 f0 1f 76 62 36 63 68 73 2e 64 6c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

