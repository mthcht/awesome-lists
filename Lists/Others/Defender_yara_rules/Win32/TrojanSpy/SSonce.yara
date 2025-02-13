rule TrojanSpy_Win32_SSonce_B_2147650496_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/SSonce.B"
        threat_id = "2147650496"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "SSonce"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 c8 66 c7 45 cc 01 00 66 c7 45 ce 20 00 c7 45 c0 28 00 00 00 6a 00}  //weight: 1, accuracy: High
        $x_1_2 = {83 e8 02 74 0b 48 74 16 48 74 21 48 74 2c eb 38}  //weight: 1, accuracy: High
        $x_1_3 = {43 46 47 00 ff ff ff ff 01 00 00 00 23 00}  //weight: 1, accuracy: High
        $x_1_4 = {0f 84 86 00 00 00 50 a1 ?? ?? 44 00 50 e8 ?? ?? fe ff 85 c0}  //weight: 1, accuracy: Low
        $x_1_5 = {0f 84 89 00 00 00 68 05 01 00 00 8d 85 f7 fe ff ff 50 e8 ?? ?? fe ff 50 e8 ?? ?? fe ff 8d 85 f0 fe ff ff 8d 95 f7 fe ff ff b9 05 01 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = "TCnRawKeyBoard" ascii //weight: 1
        $x_1_7 = "uRegistry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_SSonce_C_2147652980_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/SSonce.C"
        threat_id = "2147652980"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "SSonce"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\keylog.dat" ascii //weight: 1
        $x_1_2 = {7c 44 49 52 23 30 23 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 74 75 62 70 61 74 68 00}  //weight: 1, accuracy: High
        $x_1_4 = "[shift]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_SSonce_C_2147652980_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/SSonce.C"
        threat_id = "2147652980"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "SSonce"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ba e9 03 00 00 e8 ?? ?? ?? ?? 8d 95 ?? fb ff ff b9 e9 03 00 00 8b 45 ?? e8 ?? ?? ?? ?? 8b d8 8b 45 ?? 80 78 0c 00}  //weight: 3, accuracy: Low
        $x_1_2 = {05 06 00 00 00 00 00 00 00 00 00 01 00 00 07 08 09 0a 04 00 00 00 00 00 02 03 00 00 00 00 00 00 00 00 00 00 0b}  //weight: 1, accuracy: High
        $x_1_3 = "uKeyLogger" ascii //weight: 1
        $x_1_4 = "PcnRawinput" ascii //weight: 1
        $x_1_5 = "uEncryption" ascii //weight: 1
        $x_1_6 = "uParser" ascii //weight: 1
        $x_1_7 = "_SocketUnit" ascii //weight: 1
        $x_1_8 = "uRemoteShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

