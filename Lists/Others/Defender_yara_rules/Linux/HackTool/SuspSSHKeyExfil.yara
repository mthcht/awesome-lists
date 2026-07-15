rule HackTool_Linux_SuspSSHKeyExfil_PA_2147973720_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspSSHKeyExfil.PA"
        threat_id = "2147973720"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspSSHKeyExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {74 00 61 00 72 00 20 00 [0-48] 61 00 75 00 74 00 68 00 6f 00 72 00 69 00 7a 00 65 00 64 00 5f 00 6b 00 65 00 79 00 73 00 [0-4] 7c 00 [0-4] 63 00 75 00 72 00 6c 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 10, accuracy: Low
        $x_10_2 = {74 00 61 00 72 00 20 00 [0-48] 61 00 75 00 74 00 68 00 6f 00 72 00 69 00 7a 00 65 00 64 00 5f 00 6b 00 65 00 79 00 73 00 [0-4] 7c 00 [0-4] 77 00 67 00 65 00 74 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

