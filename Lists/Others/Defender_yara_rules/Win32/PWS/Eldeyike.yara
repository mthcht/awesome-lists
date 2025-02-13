rule PWS_Win32_Eldeyike_A_2147639099_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Eldeyike.A"
        threat_id = "2147639099"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Eldeyike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "www.linkinside.co.kr" ascii //weight: 5
        $x_1_2 = {6c 69 6e 6b 69 6e 73 69 64 65 76 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = {6c 69 6e 6b 69 6e 73 69 64 65 5f 63 6f 6e 69 66 67 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_4 = {6c 69 6e 6b 69 6e 73 69 64 65 73 5f 73 70 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

