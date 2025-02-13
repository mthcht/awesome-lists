rule Trojan_Win32_Mutelat_B_2147688979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mutelat.B"
        threat_id = "2147688979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mutelat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\MuteInstall\\Release\\MuteInstall.pdb" ascii //weight: 2
        $x_1_2 = {6d 75 74 65 69 6e 73 74 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = "offer_id=(\\w+)&aff_id=(\\w+)&transaction_id=([\\w-]+)$" ascii //weight: 1
        $x_1_4 = {4a 61 76 61 20 49 6e 73 74 61 6c 6c 65 72 20 69 6e 73 74 61 6c 6c 20 70 72 6f 67 72 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {49 6e 73 74 61 6c 6c 20 59 6f 75 72 20 53 6f 66 74 77 61 72 65 00 00 00 23 33 32 37 37 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

