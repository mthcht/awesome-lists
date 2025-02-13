rule Trojan_Win32_ErStealer_PA_2147838298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ErStealer.PA!MTB"
        threat_id = "2147838298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ErStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 99 21 ed 7c f7 e1 c1 ea 19 0f be c2 6b c0 ?? 2c 30 02 c1 30 44 0d f8 41 83 f9 07 7c}  //weight: 10, accuracy: Low
        $x_1_2 = {55 8b ec a1 ?? ?? ?? ?? 83 e0 1f 6a 20 59 2b c8 8b 45 08 d3 c8 33 05}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c8 8b 1e 83 e1 ?? 8b 7e ?? 33 d8 8b 76 ?? 33 f8 33 f0 d3 cf d3 ce d3 cb 3b fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

