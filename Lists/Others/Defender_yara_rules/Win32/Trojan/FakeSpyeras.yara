rule Trojan_Win32_FakeSpyeras_148584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSpyeras"
        threat_id = "148584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpyeras"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 25 00 53 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 2e 00 70 00 68 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {54 00 52 00 51 00 57 00 41 00 2d 00 35 00 34 00 53 00 47 00 47 00 2d 00 36 00 4c 00 53 00 57 00 50 00 2d 00 33 00 42 00 46 00 36 00 46 00 2d 00 54 00 4b 00 46 00 4c 00 4f 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "This Trojan using spoofing in order to steal confidential information from VISA users." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

