rule HackTool_Linux_SystemShutdownReboot_A_2147789060_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SystemShutdownReboot.A"
        threat_id = "2147789060"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SystemShutdownReboot"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "halt" wide //weight: 1
        $x_1_2 = "poweroff" wide //weight: 1
        $x_1_3 = "shutdown" wide //weight: 1
        $x_1_4 = "reboot" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_Linux_SystemShutdownReboot_B_2147789061_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SystemShutdownReboot.B"
        threat_id = "2147789061"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SystemShutdownReboot"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "init 0" wide //weight: 1
        $x_1_2 = "init 6" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

