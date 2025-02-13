rule Trojan_Win32_TurtleSimple_A_2147781129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurtleSimple.A!dha"
        threat_id = "2147781129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurtleSimple"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|S|S|I| |(|S|i|m|p|l|e| |S|h|e|l|l|c|o|d|e| |I|n|j|e|c|t|o|r|)|" ascii //weight: 1
        $x_1_2 = "Ready? Go!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

