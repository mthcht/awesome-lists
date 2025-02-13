rule VirTool_O97M_Evlag_A_2147812763_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:O97M/Evlag.A!MTB"
        threat_id = "2147812763"
        type = "VirTool"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Evlag"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 76 69 72 6f 6e 28 [0-5] 41 70 70 44 61 74 61 [0-5] 29 [0-16] 26 [0-16] 5c 4d 69 63 72 6f 73 6f 66 74}  //weight: 1, accuracy: Low
        $x_1_2 = "Microsoft.XMLHTTP" ascii //weight: 1
        $x_1_3 = "0006F03A-0000-0000-C000-000000000046" ascii //weight: 1
        $x_1_4 = {2e 52 75 6e [0-16] 63 [0-16] 73 [0-16] 63 [0-16] 72 [0-16] 69 [0-16] 70 [0-16] 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

