rule HackTool_Win32_Pdridopoc_A_2147829411_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Pdridopoc.A"
        threat_id = "2147829411"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Pdridopoc"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Must provide an exploit" ascii //weight: 1
        $x_1_2 = "[-] Exploit failed!" ascii //weight: 1
        $x_1_3 = "[+] Driver staged!" ascii //weight: 1
        $x_1_4 = "concealed_position" ascii //weight: 1
        $x_1_5 = {6c 00 70 00 74 00 31 00 3a 00 [0-4] 57 00 69 00 6e 00 50 00 72 00 69 00 6e 00 74 00}  //weight: 1, accuracy: Low
        $x_1_6 = "Turn off password protected sharing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

