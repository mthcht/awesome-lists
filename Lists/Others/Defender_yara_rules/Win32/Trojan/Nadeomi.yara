rule Trojan_Win32_Nadeomi_A_2147684711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nadeomi.A"
        threat_id = "2147684711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nadeomi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 5c 6d 69 6e 65 72 5c 73 74 61 72 74 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_2 = "\\wincheck.vbs" ascii //weight: 1
        $x_1_3 = {00 44 72 6f 70 65 72 44 65 6d 6f 00}  //weight: 1, accuracy: High
        $x_1_4 = "oEnv(\"SEE_MASK_NOZONECHECKS\") = 1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

