rule Backdoor_Script_RogueSpy_F_2147945894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Script/RogueSpy.F!dha"
        threat_id = "2147945894"
        type = "Backdoor"
        platform = "Script: "
        family = "RogueSpy"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl.exe -x" wide //weight: 1
        $x_1_2 = "socks5h://127.0.0.1:9050 http://" wide //weight: 1
        $x_1_3 = ".onion" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

