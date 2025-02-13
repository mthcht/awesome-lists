rule Ransom_Win32_Malaycrpt_A_2147730503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Malaycrpt.A!bit"
        threat_id = "2147730503"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Malaycrpt"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\HOW TO DECRYPT FILES.txt" ascii //weight: 1
        $x_1_2 = "http://crypt443sgtkyz4l.onion" ascii //weight: 1
        $x_1_3 = ".*?\\.crypt" ascii //weight: 1
        $x_1_4 = "\\ntuser.profile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

