rule TrojanSpy_Win32_Abcrem_A_2147621854_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Abcrem.A"
        threat_id = "2147621854"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Abcrem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "RUNDLL32.exe \"%s\",ExRundll 0xAA" ascii //weight: 5
        $x_1_2 = {5f 6b 61 73 70 65 72 73 6b 79 00 00 62 65 30 38 2e 74 6d 70}  //weight: 1, accuracy: High
        $x_1_3 = {49 6e 74 65 72 6e 00 00 65 74 4f 00 70 65 6e 55 00 00 00 00 72 6c 41}  //weight: 1, accuracy: High
        $x_1_4 = {63 61 70 43 72 00 00 00 65 61 74 65 43 61 70 74 00 00 00 00 75 72 65 57 69 6e 00 00 64 6f 77 41}  //weight: 1, accuracy: High
        $x_1_5 = "V L@ve Y@u,$hat Ab@ut Y@u" ascii //weight: 1
        $x_10_6 = {8d 85 f8 fe ff ff 50 6a 01 53 68 44 5a 01 10 ff 75 fc ff 15 00 10 01 10}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

