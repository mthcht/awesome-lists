rule Backdoor_Win32_DarkEnergy_A_2147724762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/DarkEnergy.A!bit"
        threat_id = "2147724762"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkEnergy"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 50 61 6e 65 6c 2f 63 61 6c 6c 62 61 63 6b 2e 70 68 70 [0-48] 31 38 35 2e 31 37 37 2e 35 39 2e 31 37 39}  //weight: 1, accuracy: Low
        $x_1_2 = "f4cky0ukasperskyyouwillnevergetfr3shsampleofthisbl4cken3rgy" ascii //weight: 1
        $x_1_3 = {6b 61 73 70 65 72 73 6b 79 [0-16] 74 72 65 6e 64 6d 69 63 72 6f [0-16] 74 72 75 73 74 6c 6f 6f 6b}  //weight: 1, accuracy: Low
        $x_1_4 = "},\"plugin_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

