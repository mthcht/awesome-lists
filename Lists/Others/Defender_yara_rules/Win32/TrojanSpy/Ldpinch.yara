rule TrojanSpy_Win32_Ldpinch_UQ_2147602293_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ldpinch.UQ"
        threat_id = "2147602293"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldpinch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Subject: Passwords from ld-pinch (%s)" ascii //weight: 1
        $x_1_2 = "Subject: Test from ld-pinch" ascii //weight: 1
        $x_1_3 = {5c 50 69 6e 63 68 2e 65 78 65 20 50 69 6e 63 68 2e 6f 62 6a 20 72 73 72 63 2e 6f 62 6a 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "Decrypt MS Outlook/Outlook Express passwords." ascii //weight: 1
        $x_1_5 = {50 69 6e 63 68 2e 65 78 65 00 00 00 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

