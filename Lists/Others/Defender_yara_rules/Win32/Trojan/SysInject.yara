rule Trojan_Win32_SysInject_A_2147744632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SysInject.A!MSR"
        threat_id = "2147744632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SysInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "&Start Loging" wide //weight: 1
        $x_1_2 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-20] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "default.log" ascii //weight: 1
        $x_1_4 = {6a 00 6a 00 6a 00 6a 00 ff 15 3c 62 48 00 6a 00 6a 00 6a 00 6a 00 ff 15 3c 62 48 00 6a 00 6a 00 6a 00 6a 00 ff 15 3c 62 48 00 6a 00 6a 00 6a 00 6a 00 ff 15 3c 62 48 00 6a 00 6a 00 6a 00 6a 00 ff 15 3c 62 48 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

