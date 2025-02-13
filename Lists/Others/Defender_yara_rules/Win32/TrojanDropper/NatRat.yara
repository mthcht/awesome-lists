rule TrojanDropper_Win32_NatRat_A_2147752122_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/NatRat.A!MTB"
        threat_id = "2147752122"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "NatRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/c ec^h^o CreateObject(\"Wscript.Shell\").Run \"cmd" ascii //weight: 1
        $x_1_2 = {2f 63 20 63 6d 64 20 2f 63 20 63 6d 64 20 2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 20 2d 65 70 20 62 79 70 61 73 73 20 2d 66 20 [0-32] 5c 73 65 72 76 65 72 [0-16] 2e 70 73 31}  //weight: 1, accuracy: Low
        $x_1_3 = {2c 20 30 2c 20 46 61 6c 73 65 20 3e 20 25 61 70 70 64 61 74 61 25 5c [0-16] 2e 76 62 5e 73 26 20 77 73 63 72 69 70 74 20 25 61 70 70 64 61 74 61 25 5c [0-16] 2e 76 62 5e 73 26 20 64 65 6c 20 25 61 70 70 64 61 74 61 25 5c [0-16] 2e 76 62 5e 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

