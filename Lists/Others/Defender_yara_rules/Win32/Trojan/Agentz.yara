rule Trojan_Win32_Agentz_A_2147949422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agentz.A!MTB"
        threat_id = "2147949422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agentz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 2f cb f0 33 1c 7f 69 15 67 54 41 12 59 ee 70 61 9e 3a 91 a3 99 bf 69 54 3c ec 9a ee cf bd 4c 3f f7 c5 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agentz_B_2147949423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agentz.B!MTB"
        threat_id = "2147949423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agentz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 61 49 ff 72 74 6e ff 77 57 00 ff 5f 70 6f ff 79 42 00 ff 6f 68 63 ff 36 31 47 ff 69 66 48 ff 67 45 57 ff 4f 74 65 ff 44 70 6f ff 72 00 76 ff 6e 42 4b ff 57 78 38 ff 4f 70 49 ff 00 72 65 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agentz_C_2147949424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agentz.C!MTB"
        threat_id = "2147949424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agentz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 0c 05 20 00 12 81 c9 09 20 02 01 12 81 cd 11 81 c5 07 20 02 01 11 81 31 0c 05 20 00 11 81 11 07 20 04 01 08 08 08 08 09 20 02 01 12 81 0d 11 81 c5 05 00 00 11 81 31 06 20 01 01 11 81 31 0f 07 06 08 02 15 11 80 f9 01 12 34 12 34 02 08 05 20 01 13 00 08 04 07 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agentz_D_2147949425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agentz.D!MTB"
        threat_id = "2147949425"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agentz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff cb 44 8b 14 9e 4d 03 d3 66 45 39 2a 75 54 45 8b cc 41 b8 f3 e7 50 b5 49 8b c2 0f 1f 44 00 00 0f b7 00 41 8b c8 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

