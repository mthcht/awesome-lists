rule Trojan_Win32_JosEncrypt_LK_2147853258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/JosEncrypt.LK!MTB"
        threat_id = "2147853258"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "JosEncrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Release\\FullStart.pdb" ascii //weight: 1
        $x_1_2 = "RECOVERY.txt" wide //weight: 1
        $x_1_3 = "YOUR KEY:" wide //weight: 1
        $x_1_4 = ".josep" wide //weight: 1
        $x_1_5 = {68 10 27 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

