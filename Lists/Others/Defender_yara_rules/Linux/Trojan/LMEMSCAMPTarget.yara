rule Trojan_Linux_LMEMSCAMPTarget_LMEMSCAMPShellcodeReboot_2147765794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/LMEMSCAMPTarget!!LMEMSCAMPShellcodeReboot"
        threat_id = "2147765794"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "LMEMSCAMPTarget"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "This is an lmems test sig" ascii //weight: 1
        $x_2_2 = "Used for engine CAMP functional testing" ascii //weight: 2
        $x_3_3 = {ba dc fe 21 43 be 69 19 12 28 bf ad de e1 fe b0 a9 0f 05}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

