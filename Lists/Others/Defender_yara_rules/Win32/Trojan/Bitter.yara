rule Trojan_Win32_Bitter_A_2147719409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bitter.A!bit"
        threat_id = "2147719409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitter"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 0f fe ca 88 11 41 83 ed 01 75}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 01 fe c2 88 10 40 83 ee 01 75}  //weight: 1, accuracy: High
        $x_1_3 = "reg add HKCU\\Software\\Microsoft\\Windows\\Currentversion\\Run" ascii //weight: 1
        $x_1_4 = "b=%s&c=%s&d=%s&q=%d&r=%d&ID=%d" ascii //weight: 1
        $x_1_5 = {49 4e 46 4f 3d 00 00 00 44 57 4e 00 3c 62 72 3e 00 00 00 00 2f 66 79 66}  //weight: 1, accuracy: High
        $x_1_6 = "/qiq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

