rule Backdoor_Win32_Firwat_A_2147653198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Firwat.A"
        threat_id = "2147653198"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Firwat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 c8 2c 41 3c 01 0f 97 c2 31 c0 80 f9 61 0f 95 c0 85 c2 74 15 80 f9 62 74 10 89 3c 24 e8}  //weight: 1, accuracy: High
        $x_1_2 = "[usb+] infected drive: %s" ascii //weight: 1
        $x_1_3 = {5c 66 69 72 65 00 5c 77 61 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_4 = "NAMELESSBOT_V" ascii //weight: 1
        $x_1_5 = "[ssyn] flooding: " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

