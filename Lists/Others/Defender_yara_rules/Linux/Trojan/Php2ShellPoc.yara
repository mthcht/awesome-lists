rule Trojan_Linux_Php2ShellPoc_PA_2147981265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Php2ShellPoc.PA!MTB"
        threat_id = "2147981265"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Php2ShellPoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "g_php_connected" ascii //weight: 1
        $x_1_2 = "php_connect_wait" ascii //weight: 1
        $x_1_3 = "php_connect_start" ascii //weight: 1
        $x_1_4 = "[php] VULNERABLE %s:%d php %s" ascii //weight: 1
        $x_5_5 = "PHP2SHELL-VULN-CVE-2026-109618" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

