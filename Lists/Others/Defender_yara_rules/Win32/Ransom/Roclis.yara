rule Ransom_Win32_Roclis_2147730671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Roclis"
        threat_id = "2147730671"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Roclis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "@_RESTORE-FILES_@.txt" ascii //weight: 4
        $x_4_2 = "!-GET_MY_FILES-!.txt" ascii //weight: 4
        $x_4_3 = "#RECOVERY-PC#.txt" ascii //weight: 4
        $x_8_4 = "Z:\\stop\\sorces\\Aurora\\old_sorc\\Debug\\Ransom.pdb" ascii //weight: 8
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}

