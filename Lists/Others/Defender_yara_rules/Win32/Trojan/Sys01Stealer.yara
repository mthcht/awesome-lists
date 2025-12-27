rule Trojan_Win32_Sys01Stealer_A_2147945825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sys01Stealer.A"
        threat_id = "2147945825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sys01Stealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "?machine_id=$machineId&" ascii //weight: 1
        $x_1_2 = "?a=http&dev=1&" ascii //weight: 1
        $x_1_3 = "&v={$config['version']}&" ascii //weight: 1
        $x_1_4 = "Browser(Browser::BASED_CHROMEMIUM," ascii //weight: 1
        $x_1_5 = "Browser(Browser::BASED_MOZ," ascii //weight: 1
        $x_1_6 = "shell_exec($c)" ascii //weight: 1
        $x_1_7 = "$task->save_to_current_work" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

