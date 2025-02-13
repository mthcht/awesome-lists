rule Trojan_Win64_CobaltstrikeWinGo_AX_2147908457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltstrikeWinGo.AX!MTB"
        threat_id = "2147908457"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltstrikeWinGo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 ea 01 40 8a 3c 16 8a 04 11 40 30 c7 40 88 3c 13 48 f7 c2 07 00 00 00 75 e5 48 83 fa 00 74 2b 48 f7 c2 0f 00 00 00 74 b2 48 f7 c2 07 00 00 00 75 cd 48 83 ea 08 48 8b 3c 16 48 8b 04 11 48 31 c7 48 89 3c 13 48 83 fa 10 7d}  //weight: 1, accuracy: High
        $x_1_2 = "/GobypassAV-shellcode-main/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

