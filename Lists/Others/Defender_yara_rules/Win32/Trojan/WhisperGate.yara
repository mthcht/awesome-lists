rule Trojan_Win32_WhisperGate_A_2147839191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WhisperGate.A!MTB"
        threat_id = "2147839191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WhisperGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {40 00 8d 85 f4 fb ff ff 89 04 24}  //weight: 2, accuracy: High
        $x_2_2 = {89 45 f4 eb}  //weight: 2, accuracy: High
        $x_2_3 = {8b 45 f4 89 44 24 08 c7 44 24 04 00 04 00 00 8d 85 f4 f7 ff ff 89 04 24 e8 ?? ?? 00 00 85 c0 75}  //weight: 2, accuracy: Low
        $x_2_4 = {8d 85 f4 f7 ff ff 89 44 24 04 8d 85 ?? b0 ff ff 89 04 24 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WhisperGate_B_2147894058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WhisperGate.B!MTB"
        threat_id = "2147894058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WhisperGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 f4 8b 00 89 45 e8 8b 45 e8 0f b6 c0 c7 44 24 ?? ?? ?? ?? ?? c7 44 24 08 02 00 00 00 c7 44 24 ?? ?? ?? ?? ?? 89 04 24 e8 ?? ?? ?? ?? 83 ec 10}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WhisperGate_GAN_2147899794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WhisperGate.GAN!MTB"
        threat_id = "2147899794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WhisperGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {01 c8 0f b6 00 89 c3 8b 45 e4 89 c1 c1 f9 1f 83 e1 03 01 c8 c1 f8 02 01 d8 88 02 8b 45 e8 8d 50 01 8b 45 dc 8d 0c 02 8b 45 e4 99 c1 ea 1e 01 d0 83 e0 03 29 d0 c1 e0 06 88 01 83 45 e8 02}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WhisperGate_ES_2147899954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WhisperGate.ES!MTB"
        threat_id = "2147899954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WhisperGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 0c 02 8b 55 f4 8b 45 08 01 d0 0f b6 18 8b 45 f4 99 f7 7d ec 89 d0 89 c2 8b 45 0c 01 d0 0f b6 00 31 d8 88 01 83 45 f4 01}  //weight: 10, accuracy: High
        $x_10_2 = {8b 55 f4 8b 45 08 01 d0 8b 4d f4 8b 55 08 01 ca 0f b6 1a 8b 4d f0 8b 55 0c 01 ca 0f b6 12 31 da 88 10}  //weight: 10, accuracy: High
        $x_1_3 = "tempkey" ascii //weight: 1
        $x_1_4 = "filename.dll" ascii //weight: 1
        $x_1_5 = "filename.exe" ascii //weight: 1
        $x_1_6 = "Shellcode executed successfully" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WhisperGate_RA_2147899992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WhisperGate.RA!MTB"
        threat_id = "2147899992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WhisperGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 c1 89 d8 ba 00 00 00 00 f7 f1 8b 45 0c 01 d0 0f b6 00 32 45 e7 88 06}  //weight: 10, accuracy: High
        $x_1_2 = "tempkey" ascii //weight: 1
        $x_1_3 = "Shellcode executed successfully" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WhisperGate_EC_2147903539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WhisperGate.EC!MTB"
        threat_id = "2147903539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WhisperGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "copy virus2.exe C:\\virus2.exe" ascii //weight: 1
        $x_1_2 = "REG ADD  HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run  /v  DATOS2 /t REG_SZ /d" ascii //weight: 1
        $x_1_3 = "shutdown -s -t: 10 -f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WhisperGate_GNS_2147904429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WhisperGate.GNS!MTB"
        threat_id = "2147904429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WhisperGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 55 f4 8b 45 08 8d 0c 02 8b 55 f4 8b 45 08 01 d0 0f b6 18 8b 45 f4 99 f7 7d f0 89 d0 89 c2 8b 45 0c 01 d0 0f b6 00 31 d8 88 01 83 45 f4 01 8b 45 f4 3b 45 ec}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WhisperGate_AWH_2147906422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WhisperGate.AWH!MTB"
        threat_id = "2147906422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WhisperGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 d0 0f b6 00 0f be c0 83 e8 30 83 f8 09 77 28 8d 54 24 18 8b 44 24 38 01 d0 0f b6 00 0f be c0 83 e8 30 89 44 24 34 8b 44 24 34 89 04 24}  //weight: 1, accuracy: High
        $x_1_2 = {99 f7 7c 24 30 89 44 24 3c 90 8b 44 24 3c 89 04 24 e8 c3 fe ff ff 83 44 24 38 01 8d 54 24 18 8b 44 24 38 01 d0 0f b6 00 84 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WhisperGate_MK_2147954067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WhisperGate.MK"
        threat_id = "2147954067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WhisperGate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c for %G in (" ascii //weight: 1
        $x_1_2 = ".pdf, .doc, .wps, .docx, " ascii //weight: 1
        $x_1_3 = ".ppt, .xls, .xlsx, .pptx, .rtf) do " ascii //weight: 1
        $x_1_4 = "forfiles /p " ascii //weight: 1
        $x_1_5 = " /s /M *%G /C " ascii //weight: 1
        $x_1_6 = "cmd /c echo @PATH" ascii //weight: 1
        $n_1_7 = "9453e881-26a8-4973-ba2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

