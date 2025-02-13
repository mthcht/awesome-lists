rule Trojan_Win32_Diple_B_2147724736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Diple.B!bit"
        threat_id = "2147724736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Diple"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b cf 8b c7 c1 e9 05 03 4d f8 c1 e0 04 03 45 f4 33 c8 8d}  //weight: 1, accuracy: High
        $x_1_2 = {04 3b 33 c8 2b f1 8b ce 8b c6 c1 e9 05 03 4d f0 c1 e0 04 03 45 ec 33 c8 8d 04 33 33 c8 8d 9b 47 86 c8 61 2b f9 83 6d 0c 01 75 b4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Diple_GMA_2147900364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Diple.GMA!MTB"
        threat_id = "2147900364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Diple"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 d8 88 07 47 8b 85 ?? ?? ?? ?? 83 e8 03 2b f8 97 83 c7 03 88 07 ff 85 ?? ?? ?? ?? ff 8d ?? ?? ?? ?? 0f 85}  //weight: 5, accuracy: Low
        $x_5_2 = {83 04 24 11 58 bb ?? ?? ?? ?? 31 18 83 c0 04 e2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Diple_GZT_2147925062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Diple.GZT!MTB"
        threat_id = "2147925062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Diple"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 56 57 68 00 82 40 00 33 f6 56 56 ff 15}  //weight: 10, accuracy: High
        $x_1_2 = "iKjhzZrhvU)yqOkm2Ckm5ZvquRe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

