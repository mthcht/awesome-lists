rule Trojan_Win32_Tbot_2147632181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tbot"
        threat_id = "2147632181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 72 65 67 69 73 74 65 72 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 45 43 53 45 52 56 45 52 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 63 6f 6d 6d 61 6e 64 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 63 74 66 6d 6f 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "dsbfjdagr4523" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

