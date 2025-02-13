rule TrojanSpy_Win32_Fakegina_E_2147657049_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Fakegina.E"
        threat_id = "2147657049"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakegina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 6c 78 4c 6f 67 67 65 64 4f 75 74 53 41 53 00 6d 73 67 69 6e 61 2e 64 6c 6c [0-5] 5c 42 72 30 57 4d 69 6e 55 53 65 72 53 2e 44 4c 4c}  //weight: 1, accuracy: Low
        $x_1_2 = "OldPass = %s" wide //weight: 1
        $x_1_3 = "Domain  = %s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

