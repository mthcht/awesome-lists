rule Trojan_Win32_YYpass_A_2147648959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/YYpass.A"
        threat_id = "2147648959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "YYpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0b 83 c3 04 8b 32 83 c2 04 f3 a4 48 75 f1}  //weight: 1, accuracy: High
        $x_1_2 = "libeita87@gmail.com" ascii //weight: 1
        $x_1_3 = {b1 bb b5 c1 59 59 c3 dc c2 eb a3 ba 00}  //weight: 1, accuracy: High
        $x_1_4 = "duospeak.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

