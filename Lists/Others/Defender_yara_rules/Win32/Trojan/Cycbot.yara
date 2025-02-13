rule Trojan_Win32_Cycbot_GP_2147923154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cycbot.GP!MTB"
        threat_id = "2147923154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cycbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 f0 c7 06 2d a9 55 1d e6 6a 24 72 7e c0 66 e0 ce b4 06 7d e4 0f f4 90 40 37 23 c0 ab ee b2 6e 41 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

