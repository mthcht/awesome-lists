rule Trojan_Win32_Ouftap_A_2147605125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ouftap.A"
        threat_id = "2147605125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ouftap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {83 e9 08 8b 1e 81 36 af 17 e5 38 31 5e 04 89 fe d1 cb fc ac 32 c1 32 c7 00 d8 aa c1 cb 03 81 f3 27 12 85 d4 81 c3 a1 53 cd 43 e2 e7}  //weight: 8, accuracy: High
        $x_8_2 = "tapi32mutex" ascii //weight: 8
        $x_1_3 = "Mask=" ascii //weight: 1
        $x_1_4 = "Broadcast=" ascii //weight: 1
        $x_1_5 = "mac not found" ascii //weight: 1
        $x_1_6 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
        $x_1_7 = "AUTOMATION" ascii //weight: 1
        $x_1_8 = "EMBEDDING" ascii //weight: 1
        $x_1_9 = "REGSERVER" ascii //weight: 1
        $x_1_10 = "\\mips.bin" ascii //weight: 1
        $x_1_11 = "\\isuninst.bin" ascii //weight: 1
        $x_1_12 = "\\\\.\\FaDevice0" ascii //weight: 1
        $x_1_13 = "24h-Ok" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 10 of ($x_1_*))) or
            ((2 of ($x_8_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ouftap_B_2147616541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ouftap.B"
        threat_id = "2147616541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ouftap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1d 53 8a 98 ?? a0 40 00 30 1c 32 8b 1d ?? a0 40 00 40 3b c3 72 02 33 c0 42 3b d7 72 e5}  //weight: 5, accuracy: Low
        $x_1_2 = "\\\\.\\FaDevice0" ascii //weight: 1
        $x_1_3 = "%s\\1.txt" ascii //weight: 1
        $x_1_4 = "tapi32d.exe was not ran" ascii //weight: 1
        $x_1_5 = "Bisuninst.bin" ascii //weight: 1
        $x_1_6 = "SYSTEM\\CurrentControlSet\\Control\\CrashImage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

