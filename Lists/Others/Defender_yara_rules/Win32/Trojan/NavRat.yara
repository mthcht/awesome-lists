rule Trojan_Win32_NavRat_A_2147727585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NavRat.A"
        threat_id = "2147727585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NavRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PrecomProc : Second Download and ShellExecute Ok" ascii //weight: 1
        $x_1_2 = "UploadProc : %s EncDecFile failed" ascii //weight: 1
        $x_1_3 = "Preproc : mapping self exe to iexplore process" ascii //weight: 1
        $x_1_4 = "PrecomExe : returned from Preproc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

