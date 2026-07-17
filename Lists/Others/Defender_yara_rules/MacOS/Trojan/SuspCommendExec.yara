rule Trojan_MacOS_SuspCommendExec_B_2147973867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspCommendExec.B"
        threat_id = "2147973867"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspCommendExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 00 6f 00 64 00 65 00 20 00 2d 00 65 00 [0-6] 63 00 6f 00 6e 00 73 00 74 00 20 00 5f 00 30 00 78 00 35 00 61 00 66 00 35 00 65 00 31 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Application Support,NodeJS" wide //weight: 1
        $x_1_3 = "process.env.LOCALAPPDATA||path[_0x" wide //weight: 1
        $x_1_4 = "{spawn}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

