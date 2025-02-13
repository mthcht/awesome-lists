rule Backdoor_WinNT_Festi_A_2147627916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Festi.A"
        threat_id = "2147627916"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Festi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff 56 be ff 00 00 00 56 e8 ?? ?? ?? ?? 84 c0 74 2e a1 ?? ?? ?? ?? 80 38 b8 75 1e 8b 0d ?? ?? ?? ?? 8b 40 01 8b 09 8d 0c 81 ba ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 5e c3}  //weight: 1, accuracy: Low
        $x_1_2 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_3 = "\\Device\\Tcp" wide //weight: 1
        $x_1_4 = "\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\GloballyOpenPorts\\List" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_WinNT_Festi_B_2147629439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Festi.B"
        threat_id = "2147629439"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Festi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "POST /update.php HTTP/1.1" ascii //weight: 1
        $x_1_2 = "\\Driver\\NTICE" wide //weight: 1
        $x_1_3 = "\\Driver\\tdx" wide //weight: 1
        $x_1_4 = "\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\GloballyOpenPorts\\List" wide //weight: 1
        $x_1_5 = {55 8b ec 51 51 ff 75 08 8d 45 f8 50 ff 15 ?? ?? ?? ?? 8d 45 f8 50 ff 15 ?? ?? ?? ?? c9 c2 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_WinNT_Festi_C_2147629440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Festi.C"
        threat_id = "2147629440"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Festi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "POST /update.php HTTP/1.1" ascii //weight: 1
        $x_1_2 = "\\Driver\\tdx" wide //weight: 1
        $x_1_3 = "\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\GloballyOpenPorts\\List" wide //weight: 1
        $x_1_4 = {fa f6 45 08 02 74 0d 50 0f 20 c0 25 ff ff fe ff 0f 22 c0 58 b0 01 5d c2 04 00}  //weight: 1, accuracy: High
        $x_1_5 = "eclipse\\botnet\\drivers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_WinNT_Festi_D_2147656868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Festi.D"
        threat_id = "2147656868"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Festi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hwbcr" wide //weight: 2
        $x_2_2 = "hwsht" wide //weight: 2
        $x_2_3 = "eclipse\\botnet\\drivers" ascii //weight: 2
        $x_1_4 = "\\Driver\\tdx" wide //weight: 1
        $x_1_5 = "\\Driver\\NTICE" wide //weight: 1
        $x_1_6 = "opera.exe" ascii //weight: 1
        $x_1_7 = "thebat.exe" ascii //weight: 1
        $x_1_8 = "thunderbird.exe" ascii //weight: 1
        $x_1_9 = "msimn.exe" ascii //weight: 1
        $x_1_10 = "telnet.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

