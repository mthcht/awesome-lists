rule HackTool_Win32_JuicyPotato_F_2147921594_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/JuicyPotato.F!dha"
        threat_id = "2147921594"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "JuicyPotato"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[*] Bruteforcing %d CLSIDs..." ascii //weight: 1
        $x_1_2 = "[*] Windows Defender Firewall not enabled. Every COM port will work." ascii //weight: 1
        $x_1_3 = "[-] The privileged process failed to communicate with our COM Server :( Try a different COM port in the -l flag." ascii //weight: 1
        $x_1_4 = "[+] authresult success %S;%S\\%S;%S" ascii //weight: 1
        $x_2_5 = "[+] Exploit successful!" ascii //weight: 2
        $x_3_6 = "JuicyPotatoNG" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

