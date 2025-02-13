rule TrojanSpy_Win32_QQpass_AA_2147596647_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/QQpass.gen!AA"
        threat_id = "2147596647"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {52 65 67 69 73 74 65 72 61 74 69 6f 6e 20 45 72 72 6f 72 21 00 00 00 00 35 35 36 72 74 72 64 68}  //weight: 10, accuracy: High
        $x_10_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_3 = "556rtrdh" ascii //weight: 10
        $x_10_4 = {ff ff ff ff 02 00 00 00 6d 6d 00 00 ff ff ff ff 03 00 00 00 64 6c 6c 00 53 74 61 72 74 48 6f 6f 6b 00 00 00 49 6e 73 74 61 6c 6c 48 6f 6f 6b 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_QQpass_A_2147648130_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/QQpass.gen!A"
        threat_id = "2147648130"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "||[]Taoist Pries" ascii //weight: 2
        $x_2_2 = "[][][][[[]]1989.`11" ascii //weight: 2
        $x_3_3 = {5b 42 61 63 6b 73 70 61 63 65 5d 00 5b 54 41 42 5d 00 5b 45 4e 54 45 52 5d 00 5b 53 48 49 46 54}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

