rule Trojan_Win32_Lopock_A_2147681130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lopock.A"
        threat_id = "2147681130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lopock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\Winlocker\\Release\\Winlocker.pdb" ascii //weight: 1
        $x_1_2 = "cmd=install&uid=%s&os=%s&version=%s" ascii //weight: 1
        $x_1_3 = {6a 04 8d 45 f4 50 6a 06 57 c7 45 f4 c0 27 09 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

