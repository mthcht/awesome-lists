rule Trojan_Win32_Swotter_BB_2147758884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Swotter.BB!MTB"
        threat_id = "2147758884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Swotter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 25 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 [0-63] 2c 50 72 65 74 6f 72}  //weight: 1, accuracy: Low
        $x_1_2 = {25 25 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 [0-63] 2c 42 65 6e 74 6c 65 79}  //weight: 1, accuracy: Low
        $x_1_3 = {25 25 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 [0-63] 2c 58 79 6c 6f 6c}  //weight: 1, accuracy: Low
        $x_2_4 = "Nullsoft Install System" ascii //weight: 2
        $x_1_5 = "%%\\rundll32.exe Ulotrichy,Screening" ascii //weight: 1
        $x_1_6 = "%%\\rundll32.exe Festoonery,Bentley" ascii //weight: 1
        $x_1_7 = "\\rundll32.exe Renovator,Wordbook" ascii //weight: 1
        $x_1_8 = "%%\\rundll32.exe Slugfest,Bentley" ascii //weight: 1
        $x_1_9 = "%%\\rundll32.exe Bridesmaid,Minyan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Swotter_BC_2147761166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Swotter.BC!MTB"
        threat_id = "2147761166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Swotter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Nullsoft Install System" ascii //weight: 2
        $x_1_2 = {25 25 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 [0-63] 2c 4d 69 6e 79 61 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

