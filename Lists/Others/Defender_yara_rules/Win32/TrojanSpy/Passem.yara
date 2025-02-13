rule TrojanSpy_Win32_Passem_A_2147678893_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Passem.A"
        threat_id = "2147678893"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Passem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Mac:%02X-%02X-%02X-%02X-%02X-%02X" ascii //weight: 3
        $x_3_2 = "cmd.exe /c %s" ascii //weight: 3
        $x_4_3 = "\\mssap32.dll" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

