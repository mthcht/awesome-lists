rule Trojan_Win32_GootKit_A_2147730193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GootKit.A!MTB"
        threat_id = "2147730193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GootKit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c0 0b 02 83 c2 04 8d 40 f0 31 f0 83 e8 01 89 c6 50 8f 07 83 c7 04 83 eb 04 8d 05 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 05 54 cb 43 00 52 65 61 64 c7 05 ?? ?? ?? ?? 50 72 6f 63 66 c7 05 ?? ?? ?? ?? 65 73 66 c7 05 ?? ?? ?? ?? 73 4d 68 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GootKit_SF_2147742571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GootKit.SF"
        threat_id = "2147742571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GootKit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 c0 0b 05 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 8b 00 01 05 ?? ?? ?? ?? 8d 35 ?? ?? ?? ?? 81 2e ?? ?? ?? ?? 0f 82 ?? ?? ?? ?? ff 36 5e 83 7d fc 00 75 02 74 11 8d 05 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 0d ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 58 01 c1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

