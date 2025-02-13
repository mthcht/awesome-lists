rule Trojan_Linux_KillFile_A_2147825142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/KillFile.A!xp"
        threat_id = "2147825142"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "KillFile"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KillProcess" ascii //weight: 1
        $x_1_2 = "tcp_connect_nblock" ascii //weight: 1
        $x_1_3 = "RunFile" ascii //weight: 1
        $x_1_4 = "abstract_url" ascii //weight: 1
        $x_1_5 = "ShellEexec" ascii //weight: 1
        $x_1_6 = "http_download" ascii //weight: 1
        $x_1_7 = "killfileandpid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

