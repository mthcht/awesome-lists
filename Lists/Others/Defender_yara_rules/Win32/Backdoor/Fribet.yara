rule Backdoor_Win32_Fribet_2147605277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Fribet"
        threat_id = "2147605277"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Fribet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "freetibet.lamalife.com" ascii //weight: 1
        $x_1_2 = "free tibet" ascii //weight: 1
        $x_1_3 = "MrxyMutex2" ascii //weight: 1
        $x_1_4 = {44 6c 6c 4e 61 6d 65 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c 69 70 73 65 63}  //weight: 1, accuracy: High
        $x_1_5 = {46 6b 53 68 75 74 64 6f 77 6e 00 00 53 74 61 72 74 75 70 00 46 6b 53 74 61 72 74 75 70 00 00 00 63 6c 61 73 73 69 64 00 46 4b 69 6e 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

