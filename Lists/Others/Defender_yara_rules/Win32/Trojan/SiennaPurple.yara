rule Trojan_Win32_SiennaPurple_A_2147826197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SiennaPurple.A!dha"
        threat_id = "2147826197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SiennaPurple"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\ForOP\\attack(utils)\\attack tools\\Backdoor\\powershell\\btlc_C\\Release\\btlc_C.pdb" ascii //weight: 2
        $x_1_2 = "----------3819074751749789153841466081" ascii //weight: 1
        $x_1_3 = {0f be 02 83 e8 30 8b 4d 08 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

