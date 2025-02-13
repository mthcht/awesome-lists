rule TrojanDropper_Win32_Randrew_B_2147718549_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Randrew.B!bit"
        threat_id = "2147718549"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Randrew"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 33 c9 80 34 01 ?? 41 3b ce 76}  //weight: 1, accuracy: Low
        $x_1_2 = "netsh advfirewall firewall add rule name=\"%s\" dir=in action=allow program=\"%s\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

