rule Trojan_Win32_Ellikic_A_2147624617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ellikic.A"
        threat_id = "2147624617"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ellikic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 45 f8 0f b6 44 38 ff 66 03 f0 66 69 c6 be 15 66 05 51 7e 8b f0 43 fe 4d f7 75 c1}  //weight: 1, accuracy: High
        $x_1_2 = "<iframe src=\"%s\" width=0 height=0></iframe>" ascii //weight: 1
        $x_1_3 = {69 65 68 65 6c 70 65 72 2e 64 6c 6c 00 44 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

