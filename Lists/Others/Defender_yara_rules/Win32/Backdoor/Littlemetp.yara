rule Backdoor_Win32_Littlemetp_A_2147749530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Littlemetp.A!dha"
        threat_id = "2147749530"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Littlemetp"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setting the filename to \"2_host.com_443.exe\" and running it without args will do exactly the same" ascii //weight: 1
        $x_1_2 = "3: bind_tcp" ascii //weight: 1
        $x_1_3 = "like TRANSPORT_LHOST_LPORT.exe" ascii //weight: 1
        $x_1_4 = "tinymet.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Littlemetp_B_2147757668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Littlemetp.B!!Littlemetp.B"
        threat_id = "2147757668"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Littlemetp"
        severity = "Critical"
        info = "Littlemetp: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {56 89 75 fc ff d3 a1 ?? ?? ?? ?? 6a 40 68 00 10 00 00 83 c0 05 50 [0-6] ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {c7 45 fc 80 33 00 00 50 6a 1f 56 ff 15 ?? ?? ?? ?? 53 53 53 53 56 ff 15 ?? ?? ?? ?? 85 c0 75 07 68 ?? ?? ?? ?? eb ?? 6a 40 68 00 10 00 00 68 00 00 40 00 53 ff 15}  //weight: 2, accuracy: Low
        $x_1_3 = {83 c4 0c a3 ?? ?? ?? 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Littlemetp_B_2147757668_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Littlemetp.B!!Littlemetp.B"
        threat_id = "2147757668"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Littlemetp"
        severity = "Critical"
        info = "Littlemetp: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setting the filename to \"2_host.com_443.exe\" and running it without args will do exactly the same" ascii //weight: 1
        $x_1_2 = "3: bind_tcp" ascii //weight: 1
        $x_1_3 = "like TRANSPORT_LHOST_LPORT.exe" ascii //weight: 1
        $x_1_4 = "tinymet.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Littlemetp_AA_2147895836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Littlemetp.AA!MTB"
        threat_id = "2147895836"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Littlemetp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c0 89 45 ?? 8b 45 ?? 8b 55 ?? 01 02 8b 45 ?? 03 45 ?? 03 45 ?? 03 45 ?? 89 45 ?? 6a 00 e8 [0-4] 8b 5d ?? 2b d8 6a 00 e8 [0-4] 2b d8 8b 45 ?? 31 18 83 45 [0-2] 83 45 [0-2] 8b 45 ?? 3b 45 ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

