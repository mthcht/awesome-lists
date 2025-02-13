rule Trojan_Win32_Noratops_A_2147693817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Noratops.A!dha"
        threat_id = "2147693817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Noratops"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 fa 40 7c ?? a8 03 0f 85 ?? ?? ?? ?? 8b d0 c1 ea 02 6a 3d 6b d2 03}  //weight: 1, accuracy: Low
        $x_1_2 = "~$com.firefox.debug.tmp" wide //weight: 1
        $x_1_3 = "Injector.dll" ascii //weight: 1
        $x_1_4 = {6a 02 53 56 e8 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? bf 6c 0e 00 00 83 c4 10 3b c7 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

