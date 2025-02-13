rule Trojan_O97M_InfoStealer_B_2147767284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/InfoStealer.B!MTB"
        threat_id = "2147767284"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"Content-Type: application/upload\" + vbCrLf + vbCrLf" ascii //weight: 1
        $x_1_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 4e 6f 72 6d 61 6c 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 20 26 20 22 20 22 20 26 20 43 68 72 28 33 38 29 20 26 20 22 20 63 6f 70 79 20 22 20 26 20 [0-10] 20 26 20 22 20 [0-10] 2e 76 62 73 22 20 26 20 22 20 22 20 26 20 43 68 72 28 33 38 29 20 26}  //weight: 1, accuracy: Low
        $x_1_3 = ".WriteLine \"  Physical (MAC) address: \" & objAdapter.MACAddress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

