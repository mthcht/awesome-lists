rule Virus_Win32_Silcer_A_2147602542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Silcer.gen!A"
        threat_id = "2147602542"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Silcer"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 72 65 61 74 65 46 69 6c 65 41 00 52 65 61 64 46 69 6c 65 00 57 72 69 74 65 46 69 6c 65 00 43 6c 6f 73 65 48 61 6e 64 6c 65 00 46 69 6e 64 46 69 72 73 74 46 69 6c 65 41 00 46 69 6e 64 4e 65 78 74 46 69 6c 65 41 00 46 69 6e 64 43 6c 6f 73 65 00 53 65 74 46 69 6c 65 50 6f 69 6e 74 65 72 00 43 72 65 61 74 65 54 68 72 65 61 64 00 45 78 69 74 54 68 72 65 61 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {2a 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "Win32.HugoBoss by VirusBuster/29A." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

