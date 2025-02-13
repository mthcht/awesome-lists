rule Trojan_Win32_Cotfuser_A_2147618716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cotfuser.A"
        threat_id = "2147618716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cotfuser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 0f b6 14 08 66 b9 ff 00 66 2b ca 0f 80 0d 01 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {81 f9 4d 5a 00 00 74 13}  //weight: 1, accuracy: High
        $x_1_3 = "cacls c:\\ /e /g everyone:f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

