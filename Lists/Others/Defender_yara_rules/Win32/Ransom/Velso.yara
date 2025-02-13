rule Ransom_Win32_Velso_AA_2147852018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Velso.AA!MTB"
        threat_id = "2147852018"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Velso"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\get_my_files.txt" ascii //weight: 1
        $x_1_2 = "Hello. If you want to return files, write me to e-mail" ascii //weight: 1
        $x_1_3 = "Velso@protonmail" ascii //weight: 1
        $x_1_4 = "velso" ascii //weight: 1
        $x_1_5 = "NSt7__cxx1110moneypunctIcLb0EEE" ascii //weight: 1
        $x_1_6 = "NSt7__cxx1114collate_bynameIcEE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

