rule Trojan_Win32_Stuc_A_2147688825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stuc.A"
        threat_id = "2147688825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stuc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NextPart_%03d_%04X_%08.8lX.%08.8lX" ascii //weight: 1
        $x_1_2 = "v=%s&i=%s&d=%d&m=%d&w=%d" ascii //weight: 1
        $x_1_3 = {66 61 6b 65 6d 78 2e 90 02 06 6d 65 73 73 61 67 65 6c 61 62 73 2e 90 02 06 62 6c 6f 63 6b 90 02 06 64 6e 73 62 6c 90 02 06 73 70 61 6d 68 61 75 73}  //weight: 1, accuracy: High
        $x_1_4 = "http://%s:%d/%s.asp" ascii //weight: 1
        $x_1_5 = "RCPT TO: <%s>" ascii //weight: 1
        $x_1_6 = "%s%02d%s.%u.qmail@%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Stuc_A_2147688853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stuc.A!!Stuc"
        threat_id = "2147688853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stuc"
        severity = "Critical"
        info = "Stuc: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NextPart_%03d_%04X_%08.8lX.%08.8lX" ascii //weight: 1
        $x_1_2 = "v=%s&i=%s&d=%d&m=%d&w=%d" ascii //weight: 1
        $x_1_3 = {66 61 6b 65 6d 78 2e 90 02 06 6d 65 73 73 61 67 65 6c 61 62 73 2e 90 02 06 62 6c 6f 63 6b 90 02 06 64 6e 73 62 6c 90 02 06 73 70 61 6d 68 61 75 73}  //weight: 1, accuracy: High
        $x_1_4 = "http://%s:%d/%s.asp" ascii //weight: 1
        $x_1_5 = "RCPT TO: <%s>" ascii //weight: 1
        $x_1_6 = "%s%02d%s.%u.qmail@%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

