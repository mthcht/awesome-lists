rule Backdoor_Win32_Siaacsia_A_2147720844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Siaacsia.A"
        threat_id = "2147720844"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Siaacsia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 72 76 69 63 65 20 73 74 61 72 74 3a 20 52 75 6e 43 6f 75 6e 74 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 65 72 76 69 63 65 20 73 74 6f 70 3a 20 52 75 6e 43 6f 75 6e 74 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = "Y:\\PROGRAMS\\000_CURRENT_WORK\\RPC_RDA\\RDP\\RDP_09\\MODULES\\RDPModule.pas" ascii //weight: 1
        $x_1_4 = {3a 20 50 72 6f 63 65 73 73 48 61 6e 64 6c 65 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {63 68 72 6f 6d 61 74 69 6e 67 [0-15] 47 6f 6f 67 6c 65 20 52 65 6d 6f 74 65 20 44 65 73 6b 74 6f 70 20 53 65 72 76 69 63 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

