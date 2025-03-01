rule Trojan_Win32_NukeSped_RS_2147748550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NukeSped.RS!MSR"
        threat_id = "2147748550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NukeSped"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VirtualFree" ascii //weight: 1
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "WS2_32.dll" ascii //weight: 1
        $x_1_4 = "WriteFile" ascii //weight: 1
        $x_1_5 = "CreateThread" ascii //weight: 1
        $x_1_6 = "CRYPT32.DLL" ascii //weight: 1
        $x_1_7 = "Software\\mthjk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NukeSped_SRP_2147835600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NukeSped.SRP!MTB"
        threat_id = "2147835600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NukeSped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 55 f0 83 c2 01 89 55 f0 81 7d f0 00 01 00 00 73 4b 8b 45 e8 03 45 f0 0f b6 00 03 45 dc 8b 4d f8 03 4d f0 0f b6 11 03 c2 33 d2 b9 00 01 00 00 f7 f1 89 55 dc 8b 55 e8 03 55 f0 8a 02 88 45 ef 8b 4d e8 03 4d f0 8b 55 e8 03 55 dc 8a 02 88 01 8b 4d e8 03 4d dc 8a 55 ef 88 11 eb a3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NukeSped_MA_2147888998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NukeSped.MA!MTB"
        threat_id = "2147888998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NukeSped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d2 8a c2 b3 88 fe c0 f6 ac 24 ?? ?? ?? ?? f6 eb 88 44 14 0c 42 81 fa ?? ?? ?? ?? 7c}  //weight: 5, accuracy: Low
        $x_5_2 = {8a 54 0c 10 8a 1c 38 32 da 03 ce 88 1c 38 81 e1 ff 00 00 00 40 3b c5 7c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

