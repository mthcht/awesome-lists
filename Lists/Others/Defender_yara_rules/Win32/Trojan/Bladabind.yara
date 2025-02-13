rule Trojan_Win32_Bladabind_RPI_2147826125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bladabind.RPI!MTB"
        threat_id = "2147826125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bladabind"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 01 81 c1 04 00 00 00 09 df 39 f1 75 ed}  //weight: 1, accuracy: High
        $x_1_2 = {31 03 81 ee ?? ?? ?? ?? 81 c3 04 00 00 00 39 d3 75 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

