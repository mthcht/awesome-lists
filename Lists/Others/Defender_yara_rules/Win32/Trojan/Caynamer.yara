rule Trojan_Win32_Caynamer_MR_2147781781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Caynamer.MR!MTB"
        threat_id = "2147781781"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Caynamer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d8 85 40 00 [0-2] e8 [0-14] 31 [0-3] 81 [0-12] 09 ?? 39 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Caynamer_W_2147782478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Caynamer.W!MTB"
        threat_id = "2147782478"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Caynamer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {55 8b ec 8b 45 0c 33 45 10 8b 4d 08 89 01 5d c2 0c}  //weight: 10, accuracy: High
        $x_10_2 = {8b 45 f4 8b 4d c8 d3 e0 89 45 e4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Caynamer_ACY_2147902449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Caynamer.ACY!MTB"
        threat_id = "2147902449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Caynamer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 50 8b 81 20 01 00 00 0b 44 24 34 33 46 64 50 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

