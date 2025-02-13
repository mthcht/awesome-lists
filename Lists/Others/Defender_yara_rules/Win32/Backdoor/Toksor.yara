rule Backdoor_Win32_Toksor_A_2147777150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Toksor.A"
        threat_id = "2147777150"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Toksor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "toxcore" ascii //weight: 1
        $x_1_2 = "toxEsave" ascii //weight: 1
        $x_1_3 = "node.tox.biribiri.org" ascii //weight: 1
        $x_1_4 = "tox.initramfs.io" ascii //weight: 1
        $x_1_5 = "tox.abilinski.com" ascii //weight: 1
        $x_1_6 = {21 73 79 73 69 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_7 = {21 65 78 65 63 00}  //weight: 1, accuracy: High
        $x_1_8 = {21 77 67 65 74 00}  //weight: 1, accuracy: High
        $x_1_9 = {21 75 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_10 = {21 73 68 65 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_11 = {21 6c 6f 61 64 6c 69 62 72 61 72 79 00}  //weight: 1, accuracy: High
        $x_1_12 = {21 73 74 61 72 74 70 72 6f 78 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

