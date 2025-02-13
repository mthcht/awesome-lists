rule Trojan_Win32_FakeChrome_2147755571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeChrome!MTB"
        threat_id = "2147755571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeChrome"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 6f 6f 67 6c 65 43 68 72 6f 6d 65 2d [0-5] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "Software\\Citrix\\Dazzle" ascii //weight: 1
        $x_1_3 = "ICA Client\\SelfServicePlugin\\SelfService.exe" ascii //weight: 1
        $x_1_4 = {74 00 64 00 6c 00 31 00 [0-16] 2d 00 [0-32] 40 00 40 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 6c 00 65 00 72 00 2e 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 20 00 43 00 68 00 72 00 6f 00 6d 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

