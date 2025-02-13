rule VirTool_WinNT_Oanum_2147575034_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Oanum!sys"
        threat_id = "2147575034"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Oanum"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f 20 c0 89 45 e0 25 ff ff fe ff 0f 22 c0 fa}  //weight: 2, accuracy: High
        $x_2_2 = {83 7d fc 2b 72 be fb 8b}  //weight: 2, accuracy: High
        $x_2_3 = {fb 8b 45 e0 0f 22 c0 6a 01}  //weight: 2, accuracy: High
        $x_2_4 = "feresys" ascii //weight: 2
        $x_1_5 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_6 = "ZwQuerySystemInformation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

