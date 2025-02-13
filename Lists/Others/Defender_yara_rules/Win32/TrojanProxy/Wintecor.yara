rule TrojanProxy_Win32_Wintecor_A_2147610401_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Wintecor.A"
        threat_id = "2147610401"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wintecor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 fb 05 72 ?? 8b cb 8b 14 24 8b c5 e8 ?? ?? ff ff 8b c5 8b d0 03 d3 c6 02 e9 2b f0 2b f3 83 ee 05 42 89 32}  //weight: 3, accuracy: Low
        $x_1_2 = "[Cc]ontent-[Tt]ype:[^" ascii //weight: 1
        $x_1_3 = {4c 6f 63 61 74 69 6f 6e 3a 20 68 74 74 70 3a 2f 2f [0-16] 2f 61 76 69 72 2f 72 65 64 69 72 2e 70 68 70 3f}  //weight: 1, accuracy: Low
        $x_1_4 = "HTTP/1[.][10x] ([1-5][0-9][0-9])[^" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

