rule Trojan_Win32_DllSideloadz_A_2147955359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllSideloadz.A!MTB"
        threat_id = "2147955359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllSideloadz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 44 2c 1c 88 44 3c 1c 47 88 5c 2c 1c 81 ff 00 01 00 00 7c c6 8b bc 24 1c 01 00 00 33 f6 85 ff 7e 56 33 db 33 ed 43}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4f 3c 8b b4 39 98 00 00 00 8b 94 39 9c 00 00 00 03 f7 33 c9 85 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

