rule PWS_Win32_Whibonline_A_2147583268_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Whibonline.gen!A"
        threat_id = "2147583268"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Whibonline"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {59 42 5f 4f 6e 6c 69 6e 65 43 6c 69 65 6e 74 00 44 33 44 20 57 69 6e 64 6f 77}  //weight: 3, accuracy: High
        $x_1_2 = "#32770" ascii //weight: 1
        $x_1_3 = "GetPass" ascii //weight: 1
        $x_1_4 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_5 = "MAIL FROM: <" ascii //weight: 1
        $x_1_6 = "RCPT TO: <" ascii //weight: 1
        $x_1_7 = "Explorer.exe" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

