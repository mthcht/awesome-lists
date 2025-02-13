rule Trojan_O97M_Doroppa_A_2147731873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Doroppa.A"
        threat_id = "2147731873"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Doroppa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<![CDATA[ var r = new ActiveXObject(\"\"WScript.Shell\"\").Run(" ascii //weight: 1
        $x_1_2 = {72 65 67 73 76 72 33 32 2e 65 78 65 20 2f 73 20 2f 6e 20 2f 75 20 2f 69 3a 22 20 2b 20 [0-16] 20 2b 20 22 20 73 63 72 6f 62 6a 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {74 65 6d 70 5f 64 69 72 20 2b 20 22 5c [0-16] 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 [0-16] 2c 20 32 2c 20 54 72 75 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

