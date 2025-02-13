rule Trojan_Win64_Icxikil_A_2147706591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icxikil.A"
        threat_id = "2147706591"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icxikil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Device\\KILLIS" wide //weight: 1
        $x_1_2 = "Sysenter hooked" ascii //weight: 1
        $x_1_3 = "&ri=%s&mc=%s&vs=%s&dq=%s&sd=%s&os=%s&sc=%s&tm=%s&key=%s" ascii //weight: 1
        $x_1_4 = "feitu32Ej64\\ProcessOper\\Win7Release\\ProcessOper.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

