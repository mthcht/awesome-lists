rule Backdoor_Win64_TurtleLoader_UIN_2147805680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/TurtleLoader.UIN!dha"
        threat_id = "2147805680"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "TurtleLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@[*] Calling the Callback Function ..." ascii //weight: 1
        $x_1_2 = "@[+] Shellcode is successfully placed between 0x" ascii //weight: 1
        $x_1_3 = "@[-] Invalid UUID String Detected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

