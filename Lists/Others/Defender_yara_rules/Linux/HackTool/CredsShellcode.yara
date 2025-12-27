rule HackTool_Linux_CredsShellcode_A_2147952726_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/CredsShellcode.A"
        threat_id = "2147952726"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "CredsShellcode"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 2f 62 69 6e 2f 73 68 00 99 50 54 5f 52 66 68 2d 63 54 5e 52 e8 10 00 00 00 63 61 74 20 2f 65 74 63 2f 70 61 73 73 77 64 00 56 57 54 5e 6a 3b 58 0f 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

