rule Backdoor_Win32_Budu_2147582335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Budu"
        threat_id = "2147582335"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Budu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2a 00 5c 00 41 00 45 00 3a 00 5c 00 62 00 6f 00 74 00 6e 00 65 00 74 00 5c 00 [0-10] 41 00 6e 00 74 00 69 00 58 00 5c 00 41 00 6e 00 74 00 69 00 58 00 5c 00 41 00 6e 00 74 00 69 00 58 00 2e 00 76 00 62 00 70 00}  //weight: 3, accuracy: Low
        $x_3_2 = {6d 00 61 00 72 00 64 00 69 00 6e 00 34 00 37 00 00 00 00 00 22 00 00 00 75 00 69 00 33 00 61 00 38 00 39 00 67 00 74 00 6a 00 68 00 61 00 67 00 61 00 67 00 73 00 6a 00 69 00}  //weight: 3, accuracy: High
        $x_3_3 = {61 00 2e 00 6e 00 2e 00 74 00 2e 00 69 00 2e 00 78 00 00 00 1e 00 00 00 61 00 2e 00 6e 00 2e 00 74 00 2e 00 69 00 2e 00 78 00 2e 00 62 00 2e 00 6f 00 2e 00 74 00}  //weight: 3, accuracy: High
        $x_3_4 = "\\tmpfile123.exe" wide //weight: 3
        $x_2_5 = "[Download] - Executed" wide //weight: 2
        $x_2_6 = "[Download] - Successfully executed" wide //weight: 2
        $x_2_7 = "UPDATE] - Updated!" wide //weight: 2
        $x_2_8 = "Profile doesnt exist!" wide //weight: 2
        $x_2_9 = {4e 00 49 00 43 00 4b 00 20 00 00 00 0a 00 00 00 55 00 53 00 45 00 52 00}  //weight: 2, accuracy: High
        $x_1_10 = "5850505589E55753515231C0EB0EE8xxxxx01x83F802742285C074258B45103D0080000074433D01800000" wide //weight: 1
        $x_1_11 = "745BE8200000005A595B5FC9C21400E813000000EBF168xxxxx02x6AFCFF750CE8xxxxx03xEBE0FF7518FF" wide //weight: 1
        $x_1_12 = "7514FF7510FF750C68xxxxx04xE8xxxxx05xC3BBxxxxx06x8B4514BFxxxxx07x89D9F2AF75B629CB4B8B1C9D" wide //weight: 1
        $x_1_13 = "xxxxx08xEB1DBBxxxxx09x8B4514BFxxxxx0Ax89D9F2AF759729CB4B8B1C9Dxxxxx0Bx895D088B1B8B5B1C" wide //weight: 1
        $x_1_14 = "CSocketPlus.RecvData" wide //weight: 1
        $x_2_15 = "[SYSINFO] - Computer Name:" wide //weight: 2
        $x_1_16 = "ping 127.0.0.1" wide //weight: 1
        $x_1_17 = {43 00 53 00 6f 00 63 00 6b 00 65 00 74 00 50 00 6c 00 75 00 73 00 2e 00 47 00 65 00 74 00 44 00 61 00 74 00 61 00 00 00 3e 00 00 00 4f 00 4b 00 20 00 42 00 79 00 74 00 65 00 73 00 20 00 6f 00 62 00 74 00 61 00 69 00 6e 00 65 00 64 00 20 00 66 00 72 00 6f 00 6d 00 20 00 62 00 75 00 66 00 66 00 65 00 72 00 3a 00 20 00 00 00 24 00 00 00 43 00 53 00 6f 00 63 00 6b 00 65 00 74 00 50 00 6c 00 75 00 73 00 2e 00 4c 00 69 00 73 00 74 00 65 00 6e 00 00 00 00 00 26 00 00 00 53 00 54 00 41 00 54 00 45 00 3a 00 20 00 73 00 63 00 6b 00 4c 00 69 00 73 00 74 00 65}  //weight: 1, accuracy: High
        $x_1_18 = "Socket is already connected." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 6 of ($x_2_*))) or
            ((4 of ($x_3_*) and 8 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

