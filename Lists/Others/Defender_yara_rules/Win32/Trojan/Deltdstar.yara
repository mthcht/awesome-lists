rule Trojan_Win32_Deltdstar_A_2147621579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Deltdstar.A"
        threat_id = "2147621579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Deltdstar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 64 73 73 2a 00 00 00 25 73 5c 25 73}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 64 00 65 00 76 00 69 00 63 00 65 00 5c 00 6e 00 61 00 6d 00 65 00 64 00 70 00 69 00 70 00 65 00 5c 00 74 00 64 00 73 00 73 00 63 00 6d 00 64 00 00 00 74 00 64 00 73 00 73 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\registry\\machine\\software\\microsoft\\windows\\currentversion\\runonce" wide //weight: 1
        $x_1_4 = {74 64 73 73 00 00 00 00 5c 5c 3f 5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 73 79 73 74 65 6d 72 6f 6f 74 5c 73 79 73 74 65 6d 33 32}  //weight: 1, accuracy: High
        $x_1_5 = {ff d7 68 bc 20 40 00 53 6a 00 ff 15 60 20 40 00 eb 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

