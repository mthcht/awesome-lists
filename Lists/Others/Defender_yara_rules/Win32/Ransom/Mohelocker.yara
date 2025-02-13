rule Ransom_Win32_Mohelocker_A_2147722803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mohelocker.A!rsm"
        threat_id = "2147722803"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mohelocker"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "400"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Many of your documents, photos, video, databases and other files are no longer accessible because they have encrypted" ascii //weight: 100
        $x_100_2 = "Ooops, Your files have been encrypted !" wide //weight: 100
        $x_100_3 = "C:\\Users\\mohamed\\Desktop\\WindowsApplication1\\WindowsApplication1\\obj\\x86\\Debug\\WindowsApplication1.pdb" ascii //weight: 100
        $x_100_4 = "__ENCAddToList" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

