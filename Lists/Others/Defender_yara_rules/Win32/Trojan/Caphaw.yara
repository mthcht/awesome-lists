rule Trojan_Win32_Caphaw_A_2147682740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Caphaw.A"
        threat_id = "2147682740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "server:%s;;;user:%s;;;pass:%s;;;port:%d;;;email:%s;;;protocol:%s" ascii //weight: 1
        $x_1_2 = "w=emaild&text=" ascii //weight: 1
        $x_1_3 = "Lite\\8.0\\sm.dat" wide //weight: 1
        $x_1_4 = {53 00 4d 00 54 00 50 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 [0-6] 48 00 54 00 54 00 50 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 [0-6] 49 00 4d 00 41 00 50 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 [0-6] 50 00 4f 00 50 00 33 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Caphaw_B_2147682775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Caphaw.B"
        threat_id = "2147682775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Caphaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "spam_mode" ascii //weight: 1
        $x_1_2 = "botnet" ascii //weight: 1
        $x_1_3 = "%s?%s&version=%i&r=%04X%04X%04X&cmd=ping&" ascii //weight: 1
        $x_1_4 = {25 73 2f 63 6c 69 65 6e 74 2e 68 74 6d 6c 3f 69 64 3d 25 73 26 6e 65 74 3d 25 73 26 6b 65 79 3d 25 73 26 63 6d 64 3d 63 66 67 [0-6] 2d 63 72 79 70 74 73 70 61 6d [0-6] 70 69 6e 67 [0-6] 74 61 73 6b}  //weight: 1, accuracy: Low
        $x_1_5 = "spamhaus.org/query/bl?ip=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

