rule Worm_Win32_Braim_A_2147598470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Braim.A"
        threat_id = "2147598470"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Braim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Arquivos de programas" ascii //weight: 2
        $x_1_2 = "MSN Messenger" ascii //weight: 1
        $x_1_3 = "log.txt" ascii //weight: 1
        $x_1_4 = "</contact>" ascii //weight: 1
        $x_1_5 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
        $x_2_6 = "Messenger nao pode ser" ascii //weight: 2
        $x_10_7 = {01 7d 01 02 03 00 04 11 05 12 21 31 41 06 13 51}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

