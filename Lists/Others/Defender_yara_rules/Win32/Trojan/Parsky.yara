rule Trojan_Win32_Parsky_A_2147719747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Parsky.A!bit"
        threat_id = "2147719747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Parsky"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\kasper\\Release\\kasper.pdb" ascii //weight: 1
        $x_1_2 = {00 72 6f 6f 74 69 6e 66 6f 23 23 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 61 67 65 6e 74 43 68 72 6f 6d 65 23 23 23 23 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 26 61 63 63 3d 37 23 23 23 23 23 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Parsky_B_2147726020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Parsky.B"
        threat_id = "2147726020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Parsky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Release\\s7.pdb" ascii //weight: 10
        $x_10_2 = "\\kasper.pdb" ascii //weight: 10
        $x_3_3 = "\\Favorites\\VLC" wide //weight: 3
        $x_3_4 = "\\Favorites\\skype" wide //weight: 3
        $x_3_5 = "stikers.php" wide //weight: 3
        $x_2_6 = "www.stikerscloud.com" wide //weight: 2
        $x_2_7 = "www.mailsinfo.net" wide //weight: 2
        $x_2_8 = "info/checkmailp.php" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

