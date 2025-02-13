rule Trojan_Win32_LuckyMiner_2147750279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LuckyMiner!MSR"
        threat_id = "2147750279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LuckyMiner"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lucky.exe" wide //weight: 1
        $x_1_2 = "LuckyMiner" wide //weight: 1
        $x_1_3 = "http://luckyminer.ru/9/gate.php" wide //weight: 1
        $x_1_4 = "Miner\\UI\\UI\\obj\\Release\\UI.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

