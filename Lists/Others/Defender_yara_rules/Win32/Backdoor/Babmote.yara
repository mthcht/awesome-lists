rule Backdoor_Win32_Babmote_A_2147644914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Babmote.A"
        threat_id = "2147644914"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Babmote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\system32\\KeyBoardA.dat" ascii //weight: 3
        $x_5_2 = "BaBy ReMoTe Get Video" ascii //weight: 5
        $x_3_3 = "\" &&  goto try ||shutdown -r -t 0" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

