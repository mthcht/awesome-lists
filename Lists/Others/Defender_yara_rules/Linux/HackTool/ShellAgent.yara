rule HackTool_Linux_ShellAgent_DK8_2147928941_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/ShellAgent.DK8"
        threat_id = "2147928941"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "ShellAgent"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 00 70 00 69 00 6e 00 67 00 33 00 20 00 [0-255] 20 00 2d 00 2d 00 66 00 69 00 6c 00 65 00 20 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_2 = {6e 00 70 00 69 00 6e 00 67 00 20 00 [0-48] 20 00 2d 00 2d 00 64 00 61 00 74 00 61 00 2d 00 73 00 74 00 72 00 69 00 6e 00 67 00 20 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_3 = "exfiltrate" wide //weight: 10
        $x_10_4 = "systemctl stop mdatp" wide //weight: 10
        $x_10_5 = "nc -u" wide //weight: 10
        $x_10_6 = "ufw disable" wide //weight: 10
        $x_10_7 = "nmap -sT " wide //weight: 10
        $x_10_8 = "cat /etc/shadow" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

