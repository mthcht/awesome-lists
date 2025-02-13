rule Backdoor_Win32_Wavipeg_A_2147686613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wavipeg.A"
        threat_id = "2147686613"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wavipeg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ft/si.php?" ascii //weight: 1
        $x_1_2 = {61 76 70 00 65 73 65 74 00 65 67 75 69}  //weight: 1, accuracy: High
        $x_1_3 = "%s=ddos&comp=%s" ascii //weight: 1
        $x_1_4 = "&comp=%s&ext=" ascii //weight: 1
        $x_1_5 = {3c 42 4b 3e 00 3c 44 4f 57 4e 3e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Wavipeg_B_2147687503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wavipeg.B"
        threat_id = "2147687503"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wavipeg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 76 70 00 65 73 65 74 00 65 67 75 69}  //weight: 1, accuracy: High
        $x_1_2 = "ddos&comp=%s" ascii //weight: 1
        $x_1_3 = "&comp=%s&ext=" ascii //weight: 1
        $x_1_4 = "%s?get&exe&comp=%s" ascii //weight: 1
        $x_1_5 = "%s?cstorage=ddos" ascii //weight: 1
        $x_1_6 = "%s?get&download&comp=%s" ascii //weight: 1
        $x_1_7 = "%s?get&module=%s&comp=%s" ascii //weight: 1
        $x_1_8 = "%s?enc&comp=%s&ext=clipboard.txt&upload_text=%s" ascii //weight: 1
        $x_1_9 = "%s?enc&comp=%s&ext=sysinfo.txt&upload_text=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

