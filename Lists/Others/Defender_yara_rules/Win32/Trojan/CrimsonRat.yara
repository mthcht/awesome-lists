rule Trojan_Win32_CrimsonRat_A_2147751826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CrimsonRat.A!MTB"
        threat_id = "2147751826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CrimsonRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "thrRuning" ascii //weight: 1
        $x_1_2 = "funThread" ascii //weight: 1
        $x_1_3 = "funStarter" ascii //weight: 1
        $x_1_4 = "list_processes" ascii //weight: 1
        $x_1_5 = "see_scren" ascii //weight: 1
        $x_1_6 = "is_screen" ascii //weight: 1
        $x_1_7 = "push_file" ascii //weight: 1
        $x_1_8 = "get_command" ascii //weight: 1
        $x_1_9 = "do_process" ascii //weight: 1
        $x_1_10 = "lookupDrives" ascii //weight: 1
        $x_1_11 = "lookupFiles" ascii //weight: 1
        $x_1_12 = "sendSearch" ascii //weight: 1
        $x_1_13 = "checkFolders" ascii //weight: 1
        $x_1_14 = "remvUser" ascii //weight: 1
        $x_1_15 = "filesLogs" ascii //weight: 1
        $x_1_16 = "set_run" ascii //weight: 1
        $x_1_17 = "notFilders" ascii //weight: 1
        $x_1_18 = "seeAccess" ascii //weight: 1
        $x_1_19 = "addFiles" ascii //weight: 1
        $x_1_20 = "lookFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CrimsonRat_A_2147751882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CrimsonRat.A!!CrimsonRat.gen!MTB"
        threat_id = "2147751882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CrimsonRat"
        severity = "Critical"
        info = "CrimsonRat: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "thrRuning" ascii //weight: 1
        $x_1_2 = "funThread" ascii //weight: 1
        $x_1_3 = "funStarter" ascii //weight: 1
        $x_1_4 = "list_processes" ascii //weight: 1
        $x_1_5 = "see_scren" ascii //weight: 1
        $x_1_6 = "is_screen" ascii //weight: 1
        $x_1_7 = "push_file" ascii //weight: 1
        $x_1_8 = "get_command" ascii //weight: 1
        $x_1_9 = "do_process" ascii //weight: 1
        $x_1_10 = "lookupDrives" ascii //weight: 1
        $x_1_11 = "lookupFiles" ascii //weight: 1
        $x_1_12 = "sendSearch" ascii //weight: 1
        $x_1_13 = "checkFolders" ascii //weight: 1
        $x_1_14 = "remvUser" ascii //weight: 1
        $x_1_15 = "filesLogs" ascii //weight: 1
        $x_1_16 = "set_run" ascii //weight: 1
        $x_1_17 = "notFilders" ascii //weight: 1
        $x_1_18 = "seeAccess" ascii //weight: 1
        $x_1_19 = "addFiles" ascii //weight: 1
        $x_1_20 = "lookFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

