rule Trojan_Java_DldrAgent_A_2147765940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/DldrAgent.A!MTB"
        threat_id = "2147765940"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "DldrAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 65 63 75 72 65 2d 64 6e 73 2d 72 65 73 6f 6c 76 65 2e 63 6f 6d 2f [0-16] 2e 70 6e 67}  //weight: 2, accuracy: Low
        $x_2_2 = {66 61 63 74 75 72 61 63 69 6f 6e 6d 78 2e 6e 65 74 2f [0-16] 2e 70 6e 67}  //weight: 2, accuracy: Low
        $x_1_3 = "Microsoft_Secure_Document_Viewer" ascii //weight: 1
        $x_1_4 = "Secure_Viewer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

