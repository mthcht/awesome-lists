rule Trojan_Linux_HidWasp_A_2147772533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/HidWasp.A!MTB"
        threat_id = "2147772533"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "HidWasp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Trojan-Hostname" ascii //weight: 1
        $x_1_2 = {78 78 64 20 2d 72 20 2d 70 20 3e 20 25 73 2e 74 6d 70 [0-2] 63 68 6d 6f 64 20 2d 2d 72 65 66 65 72 65 6e 63 65 20 25 73 20 25 73 2e 74 6d 70 [0-2] 6d 76 20 25 73 2e 74 6d 70}  //weight: 1, accuracy: Low
        $x_1_3 = "I_AM_HIDDEN" ascii //weight: 1
        $x_1_4 = "tmp.scp.XXXXXX" ascii //weight: 1
        $x_1_5 = "HIDE_THIS_SHELL" ascii //weight: 1
        $x_1_6 = "fake_processname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

