rule Trojan_Win32_SchExec_HA_2147939824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SchExec.HA!MTB"
        threat_id = "2147939824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SchExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 74 00 6e 00 [0-4] 75 00 70 00 64 00 61 00 74 00 65 00 73 00 5c 00 [0-32] 20 00 2f 00 78 00 6d 00 6c 00 [0-4] 63 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 74 00 6d 00 70 00 [0-8] 2e 00 74 00 6d 00 70 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

