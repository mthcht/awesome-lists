rule Trojan_Win32_Cerber_MR_2147811087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cerber.MR!MTB"
        threat_id = "2147811087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 f1 56 88 88 02 30 41 00 8a 88 03 30 41 00 84 c9 74 0e 80 f9 56 74 09 80 f1 56 88 88 03 30 41 00 8a 88 04 30 41 00 84 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cerber_MPI_2147811596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cerber.MPI!MTB"
        threat_id = "2147811596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 20 e8 00 00 00 00 58 05 ?? ?? ?? ?? ff 20 e8 00 00 00 00 58 05 ?? ?? ?? ?? ff 20 e8 00 00 00 00 58 05 ?? ?? ?? ?? ff 20 e8 00 00 00 00 58 05 ?? ?? ?? ?? ff 20 e8 00 00 00 00 58 05 ?? ?? ?? ?? ff 20 e8 00 00 00 00 58 05 ?? ?? ?? ?? ff 20 e8 00 00 00 00 58 05 ?? ?? ?? ?? ff 20 e8 00 00 00 00 58 05 ?? ?? ?? ?? ff 20 e8 00 00 00 00 58 05 ?? ?? ?? ?? ff 20 e8 00 00 00 00 58 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cerber_DA_2147899398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cerber.DA!MTB"
        threat_id = "2147899398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c2 22 89 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 83 e8 22 89 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 6b c9 22 89 8d ?? ?? ?? ?? 8b 55 f8 33 55 f0 89 55 f8 8b 85 ?? ?? ?? ?? 83 c0 22 89 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 83 e9 22 89 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 6b d2 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cerber_ENE_2147943983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cerber.ENE!MTB"
        threat_id = "2147943983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {40 00 5c 91 40 00 dc 32 cb 01 00 c0 42 00 f8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

