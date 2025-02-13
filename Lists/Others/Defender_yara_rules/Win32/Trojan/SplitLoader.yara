rule Trojan_Win32_SplitLoader_B_2147911599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SplitLoader.B!dha"
        threat_id = "2147911599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SplitLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = ":\\workspace\\CBG\\Loader\\SplitLoader\\x64\\Release\\SplitLoader.pdb" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

