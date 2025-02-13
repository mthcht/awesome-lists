rule Trojan_Win32_Nuwinse_A_2147643567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nuwinse.A"
        threat_id = "2147643567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuwinse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 6e 79 77 c7 ?? ?? ?? ?? ff 68 65 72 65 c7 ?? ?? ?? ?? ff 2e 4e 45 54 88 ?? ?? ?? ?? ff e8}  //weight: 1, accuracy: Low
        $x_1_2 = {89 bd 8c c7 ff ff 3b fb 0f ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ff 44 4f 53 20 c7 85 ?? ?? ?? ff 45 52 52 4f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

