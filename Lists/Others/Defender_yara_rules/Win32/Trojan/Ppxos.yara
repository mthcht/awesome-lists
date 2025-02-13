rule Trojan_Win32_Ppxos_A_2147679646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ppxos.A"
        threat_id = "2147679646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ppxos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\MyProj\\PPProj\\Release\\PPClient.pdb" ascii //weight: 1
        $x_1_2 = "*\\shell\\sandbox" ascii //weight: 1
        $x_1_3 = "%sex%sr" ascii //weight: 1
        $x_1_4 = "/tj.php?id=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

