rule TrojanProxy_Win32_Verind_A_2147616004_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Verind.A"
        threat_id = "2147616004"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Verind"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 e2 ea c7 03 2e 65 78 65 c6 43 04 00}  //weight: 1, accuracy: High
        $x_1_2 = {83 f8 04 74 09 b8 ff 00 00 00 c9}  //weight: 1, accuracy: High
        $x_1_3 = {67 e3 0b 8b f0 ad 31 05 ?? ?? ?? ?? e2 f7 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

