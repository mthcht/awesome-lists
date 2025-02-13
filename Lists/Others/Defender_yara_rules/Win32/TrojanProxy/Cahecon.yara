rule TrojanProxy_Win32_Cahecon_A_2147686018_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Cahecon.A"
        threat_id = "2147686018"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Cahecon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%temp%\\send%_l_%.vbs" ascii //weight: 1
        $x_1_2 = {75 6f 6c 2e 63 6f 6e 68 65 63 61 61 75 6f 6c 2e 63 6f 6d 2e 62 72 2f 62 6c 61 63 6b 2f 3f [0-5] 74 69 70 6f 3d 61 6c 69 76 65 69 26 63 6c 69 65 6e 74 65 3d 74 65 73 74 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

