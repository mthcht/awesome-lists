rule Trojan_Win32_VMProtect_PGAE_2147964382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VMProtect.PGAE!MTB"
        threat_id = "2147964382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VMProtect"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\giwefkwfiw" ascii //weight: 1
        $x_1_2 = "zuhaoclient.exe" ascii //weight: 1
        $x_1_3 = "C:\\zuhao" ascii //weight: 1
        $x_1_4 = "\\LiteClient.exe" ascii //weight: 1
        $x_1_5 = "\\telnet.exe" ascii //weight: 1
        $x_1_6 = "GDI+ Hook Window Class" ascii //weight: 1
        $x_1_7 = {50 72 6f 67 6d 61 6e 00 53 48 45 4c 4c 44 4c 4c 5f 44 65 66 56 69 65 77}  //weight: 1, accuracy: High
        $x_1_8 = "\\SFHook\\release\\GP.pdb" ascii //weight: 1
        $x_1_9 = "\\pipe\\{23A9523C-3BA8-4D32-86CC-3E2D2797C18E}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

