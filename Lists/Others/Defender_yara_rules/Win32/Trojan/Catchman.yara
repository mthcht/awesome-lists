rule Trojan_Win32_Catchman_2147735902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Catchman!dha"
        threat_id = "2147735902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Catchman"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Study the net adapters to which the computer has connected" ascii //weight: 1
        $x_1_2 = "\\system32\\wbem\\tmf\\" ascii //weight: 1
        $x_1_3 = "\\Windows\\Caches\\caches_version.db" ascii //weight: 1
        $x_1_4 = "the clip filename is:" ascii //weight: 1
        $x_1_5 = "\\Microsoft\\Windows\\Burn\\" ascii //weight: 1
        $x_1_6 = "Right MENU key" ascii //weight: 1
        $x_1_7 = "Control-break processing" ascii //weight: 1
        $x_1_8 = "activing" ascii //weight: 1
        $x_1_9 = "going ahead of whatwhere" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

