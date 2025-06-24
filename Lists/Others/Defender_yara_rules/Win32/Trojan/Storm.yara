rule Trojan_Win32_Storm_LM_2147944505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Storm.LM!MTB"
        threat_id = "2147944505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Storm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {83 c9 ff f2 ae f7 d1 2b f9 57 5e 52 5f 51 5a 83 c9 ff f2 ae 52 59 4f c1 e9 02 f3 a5 52 59 83 e1 03 f3 a4 51 8b cc 89 64 24 1c 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 65 51 8d 84 24 40 01 00 00 8b cc 89 64 24 24 50}  //weight: 20, accuracy: Low
        $x_20_2 = {83 c9 ff 29 c0 f2 ae f7 d1 2b f9 51 58 57 5e 52 5f 8d 54 24 10 c1 e9 02 f3 a5 50 59 29 c0 83 e1 03 f3 a4}  //weight: 20, accuracy: High
        $x_1_3 = "STORMSERVER.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

