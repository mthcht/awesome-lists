rule Trojan_Win32_Gleishug_A_2147633526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gleishug.A"
        threat_id = "2147633526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gleishug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2e 63 6f 6d 2f 3f 73 69 64 3d [0-18] 26 73 3d 7b 73 65 61 72 63 68 54 65 72 6d 73 7d}  //weight: 3, accuracy: Low
        $x_3_2 = {2e 6e 65 74 2f 3f 73 69 64 3d [0-18] 26 73 3d 7b 73 65 61 72 63 68 54 65 72 6d 73 7d}  //weight: 3, accuracy: Low
        $x_2_3 = "\\search.sqlite\" \"UPDATE engine_data SET name = 'order' WHERE engineid LIKE '%google%'\"" ascii //weight: 2
        $x_2_4 = "\\Software\\Microsoft\\Internet Explorer\\SearchScopes" ascii //weight: 2
        $x_2_5 = "\\Mozilla Firefox\\searchplugins\\google*.xml" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Gleishug_C_2147633527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gleishug.C"
        threat_id = "2147633527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gleishug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks /create /sc minute /mo 60 /tn \"Updater\" /tr \"\\\"" ascii //weight: 1
        $x_1_2 = "Update\\seupd.exe\\\"\" /ru \"System\"" ascii //weight: 1
        $x_1_3 = "download_quiet" ascii //weight: 1
        $x_1_4 = "\\aaaa.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

